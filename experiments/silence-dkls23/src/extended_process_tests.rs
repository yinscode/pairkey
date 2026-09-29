//! Remaining process matrices; real native signing, honest shared filesystem.
use super::*;
use pairkey_dkls23_research::lifecycle::ReleaseGate;

pub(super) fn provision(dir: &Path, seed: u8) -> Result<()> {
    fs::create_dir_all(dir)?;
    for role in 0..2 {
        fs::write(
            dir.join(format!("root-{role}.bin")),
            [seed + role as u8; 32],
        )?;
    }
    Ok(())
}
async fn wait_roles(dir: &Path, roles: &[usize]) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while !roles
        .iter()
        .all(|r| dir.join(format!("{r}.reached")).exists())
    {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "targets did not reach barrier"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    Ok(())
}
fn handoffs(dir: &Path) -> Result<Vec<serde_json::Value>> {
    let mut all = vec![];
    for role in 0..2 {
        if let Ok(log) = fs::read_to_string(dir.join(format!("{role}.handoffs"))) {
            for line in log.lines() {
                all.push(serde_json::from_str(line)?);
            }
        }
    }
    Ok(all)
}
fn evidence(name: &str, value: serde_json::Value) -> Result<()> {
    if let Some(output) = std::env::var_os("PAIRKEY_ASSURANCE_EVIDENCE_DIR") {
        let output = PathBuf::from(output);
        fs::create_dir_all(&output)?;
        fs::write(
            output.join(format!("extended-{name}.json")),
            serde_json::to_vec_pretty(&value)?,
        )?;
    }
    Ok(())
}
struct ReadySign {
    request: Request,
    consumption: Option<Consumption>,
}
async fn prepare(actors: &mut Actors, key: [u8; 32]) -> Result<ReadySign> {
    if let Some(hellos) = actors.direct_hellos.clone() {
        let q = point(&hellos[0].contribution)? + point(&hellos[1].contribution)?;
        let manifest = Manifest {
            version: 1,
            key_id: key,
            identities: hellos.clone().map(|h| h.identity),
            additive_public: hellos.clone().map(|h| h.contribution),
            public_key: q.to_bytes().to_vec(),
            chain_code: digest(
                b"pairkey/dkls-research/public-chain-code/v1",
                &(key, q.to_bytes().to_vec()),
            ),
        };
        return Ok(ReadySign {
            request: Request {
                route: Route::Direct,
                manifest,
                hellos,
                entry: fresh(),
                attempt: fresh(),
                path: "m".into(),
                prehash: fresh(),
                fault: None,
                wallet_record: None,
            },
            consumption: None,
        });
    }
    let (record, hellos) = actors.describe(key).await?;
    let w = wallet(record.clone(), actors.endorse(&record, &hellos).await?)?;
    commit_ack_roles(&actors.commit(&w).await?, record.digest())?;
    let input = SetupInput {
        version: 1,
        recipe: 1,
        peers: actors.boots().clone().map(|b| b.identity),
        boots: actors.boots().clone().map(|b| b.generation),
        configuration: pool::configuration(),
        entry: fresh(),
    };
    let refill = actors
        .call(std::array::from_fn(|_| Operation::Setup {
            input: input.clone(),
            fault: None,
        }))
        .await?;
    ensure!(refill.len() == 2, "refill replies missing");
    let completed = match &refill[0].1 {
        Frame::PoolStatus(s) => s.completed,
        _ => anyhow::bail!("refill failure"),
    };
    ensure!(refill.iter().all(|(_,f)|matches!(f,Frame::PoolStatus(s) if s.entry==input.entry && s.input==input.digest() && s.completed==completed)),"refill agreement");
    let request = Request {
        route: Route::Pooled,
        manifest: record.manifest.clone(),
        hellos,
        entry: input.entry,
        attempt: fresh(),
        path: "m".into(),
        prehash: fresh(),
        fault: None,
        wallet_record: Some(record.digest()),
    };
    let consumption = Consumption::new(&input, completed, &request, fresh(), 1);
    Ok(ReadySign {
        request,
        consumption: Some(consumption),
    })
}
async fn sign(actors: &mut Actors, ready: &ReadySign) -> Result<Vec<(usize, Frame)>> {
    if let Some(c) = &ready.consumption {
        actors
            .call(std::array::from_fn(|_| Operation::Sign {
                request: Box::new(ready.request.clone()),
                consumption: c.clone(),
            }))
            .await
    } else {
        actors.start_direct(ready.request.clone()).await
    }
}
fn verify(frames: &[(usize, Frame)], ready: &ReadySign) -> Result<usize> {
    use signature::hazmat::PrehashVerifier;
    ensure!(frames.len() == 2, "missing signing results");
    let mut roles = [false; 2];
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&ready.request.manifest.public_key)?;
    for (role, frame) in frames {
        ensure!(*role < 2 && !roles[*role], "signing role/duplicate");
        roles[*role] = true;
        let Frame::Result(out) = frame else {
            anyhow::bail!("expected signing result");
        };
        let expected = ready
            .consumption
            .as_ref()
            .map_or_else(|| ready.request.context(), Consumption::digest);
        ensure!(
            out.role as usize == *role
                && out.context == expected
                && out.public_key == ready.request.manifest.public_key,
            "result binding"
        );
        let sig = k256::ecdsa::Signature::from_slice(&out.signature)?;
        key.verify_prehash(&ready.request.prehash, &sig)?;
        ensure!(sig.normalize_s().is_none(), "high-S");
        ensure!(
            k256::ecdsa::VerifyingKey::recover_from_prehash(
                &ready.request.prehash,
                &sig,
                k256::ecdsa::RecoveryId::from_byte(out.recovery_id).context("recovery ID")?
            )? == key,
            "recovery mismatch"
        );
    }
    Ok(frames.len())
}
pub(super) async fn publish(root: &Path, probe: &Path, role: u8, api: &str) -> Result<()> {
    // Separate process, exact ordered peers of the affected pairing.
    let mut c = command(probe, 2, "", true, false, role);
    c.env("PAIRKEY_ACTOR_STORAGE_DIR", root)
        .env("PAIRKEY_PUBLISH_API", api);
    let mut child = c
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    ensure!(child.wait().await?.success(), "publication failed");
    ensure!(
        probe.join("published").exists(),
        "no publication acknowledgment"
    );
    Ok(())
}
async fn overlap_case(stage: &str, mode: &str, role: u8, api: &str) -> Result<()> {
    let dir = Directory(std::env::temp_dir().join(format!("dkls-overlap-{:?}", fresh())));
    provision(&dir.0, 11)?;
    let p0 = dir.0.join("direct");
    let p1 = dir.0.join("pooled");
    let p2 = dir.0.join("unrelated");
    for p in [&p0, &p1, &p2] {
        fs::create_dir(p)?;
    }
    let other = dir.0.join("other");
    provision(&other, 71)?;
    // Different signer pair, same underlying authority/storage directory. This
    // checks scope isolation rather than merely choosing another filesystem.
    fs::create_dir_all(dir.0.join("controls"))?;
    std::os::unix::fs::symlink(dir.0.join("controls"), other.join("controls"))?;
    ensure!(
        fs::canonicalize(other.join("controls"))? == fs::canonicalize(dir.0.join("controls"))?,
        "unrelated pair must share the control directory"
    );
    let mut a = Actors::start_variant(&p0, &dir.0, stage, mode == "bypass", Some([7; 32])).await?;
    let mut b = Actors::start_variant(&p1, &dir.0, stage, mode == "bypass", None).await?;
    if mode != "positive" {
        a.expect_publication(role);
        b.expected_publication = a.expected_publication.clone();
    }
    let mut unrelated = Actors::start_variant(&p2, &other, "", false, None).await?;
    let ra = prepare(&mut a, [7; 32]).await?;
    let rb = prepare(&mut b, [8; 32]).await?;
    let rc = prepare(&mut unrelated, [9; 32]).await?;
    ensure!(
        ra.request.manifest.key_id != rb.request.manifest.key_id
            && ra.request.manifest.identities == rb.request.manifest.identities,
        "scope/wallet fixture"
    );
    let barrier = tokio::spawn({
        let root = dir.0.clone();
        let p0 = p0.clone();
        let p1 = p1.clone();
        let mode = mode.to_owned();
        let api = api.to_owned();
        async move {
            wait_roles(&p0, &[0, 1]).await?;
            wait_roles(&p1, &[0, 1]).await?;
            ensure!(
                [&p0, &p1]
                    .iter()
                    .all(|p| (0..2).all(|r| !p.join(format!("{r}.queued")).exists())),
                "target already queued"
            );
            if mode != "positive" {
                publish(&root, &p0, role, &api).await?;
                fs::write(p1.join("published"), [])?;
            }
            for p in [&p0, &p1] {
                fs::write(p.join("resume"), [])?;
            }
            Ok::<_, anyhow::Error>(())
        }
    });
    let (fa, fb) = tokio::join!(sign(&mut a, &ra), sign(&mut b, &rb));
    let fa = fa?;
    let fb = fb?;
    barrier.await??;
    if mode == "positive" || stage == "result" && mode == "bypass" {
        verify(&fa, &ra).context("overlapping Direct results")?;
        verify(&fb, &rb).context("overlapping pooled results")?;
    }
    a.finish().await?;
    b.finish().await?;
    let counts = [&p0, &p1].map(|p| {
        (0..2)
            .filter(|r| p.join(format!("{r}.queued")).exists())
            .count()
    });
    ensure!(
        counts == if mode == "protected" { [0, 0] } else { [2, 2] },
        "overlap queue oracle"
    );
    // Actual unrelated signing after publication, rather than only testing gate.release().
    let fc = sign(&mut unrelated, &rc).await?;
    let unrelated_results = verify(&fc, &rc).context("unrelated-pair signing results")?;
    unrelated.finish().await?;
    let pids = [&p0, &p1, &p2]
        .iter()
        .flat_map(|p| (0..2).map(move |r| fs::read_to_string(p.join(format!("{r}.pid")))))
        .collect::<std::io::Result<std::collections::BTreeSet<_>>>()?;
    ensure!(pids.len() == 6, "workers must be distinct");
    evidence(
        &format!("overlap-{stage}-{mode}-{role}-{api}"),
        serde_json::json!({"stage":stage,"mode":mode,"publisher_role":role,"publication_api":api,"overlapping_routes":["Direct","Pooled"],"different_wallets":true,"distinct_worker_processes":pids.len(),"both_attempts_targets_held_before_publication":true,"target_queue_handoffs":counts,"unrelated_pair_shares_control_directory":true,"unrelated_verified_result_frames_after_publication":unrelated_results,"passed":true}),
    )?;
    fs::write(dir.0.join("passed"), [])?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_native_process_wallet_routes_and_publication_matrix() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["r4", "result"] {
        for mode in ["protected", "positive", "bypass"] {
            for (role, api) in if mode == "protected" {
                vec![(0, "incident"), (1, "incident"), (0, "gate"), (1, "gate")]
            } else {
                vec![(0, "incident")]
            } {
                tokio::time::timeout(
                    Duration::from_secs(40),
                    overlap_case(stage, mode, role, api),
                )
                .await
                .unwrap()
                .unwrap();
            }
        }
    }
}

fn retired(root: &Path, ready: &ReadySign) -> Result<()> {
    for role in 0..2 {
        let path = root.join("controls/entries").join(format!(
            "{role}-{}.retired",
            super::super::hex(&ready.request.entry)
        ));
        ensure!(
            fs::read(path)?.len() == 32,
            "missing complete consumption tombstone"
        );
        ensure!(
            pairkey_dkls23_research::reserve(
                &root.join("controls/entries"),
                role,
                ready.request.entry,
                [1; 32]
            )
            .is_err(),
            "retired entry reacquired"
        );
    }
    Ok(())
}
fn kill(pid: u32) -> Result<()> {
    // Only parent-owned fixture PIDs are passed; never discover arbitrary peers.
    ensure!(pid > 1, "invalid fixture PID");
    ensure!(
        unsafe { libc::kill(pid as i32, libc::SIGKILL) } == 0,
        "fixture SIGKILL failed"
    );
    Ok(())
}
async fn finish_except(actors: Actors, killed: &[usize]) -> Result<()> {
    actors.finish_except(killed).await
}
async fn replace_and_sign(root: &Path, old: &ReadySign, label: &str) -> Result<usize> {
    let record_path = root.join("controls/wallets").join(format!(
        "{}.wallet",
        super::super::hex(&old.request.manifest.key_id)
    ));
    let bytes = fs::read(&record_path)?;
    let probe = root.join(label);
    fs::create_dir(&probe)?;
    let mut replacement = Actors::start_variant(&probe, root, "", false, None).await?;
    let fresh = prepare(&mut replacement, old.request.manifest.key_id).await?;
    ensure!(
        fresh.request.manifest == old.request.manifest
            && fresh.request.wallet_record == old.request.wallet_record,
        "replacement changed wallet/address"
    );
    ensure!(
        fresh.request.entry != old.request.entry && fresh.request.attempt != old.request.attempt,
        "replacement reused signing attempt"
    );
    ensure!(
        fresh.consumption.as_ref().unwrap().input != old.consumption.as_ref().unwrap().input,
        "replacement reused boot-bound preprocessing"
    );
    ensure!(
        fs::read(&record_path)? == bytes,
        "replacement rewrote immutable wallet"
    );
    let results = sign(&mut replacement, &fresh).await?;
    let count = verify(&results, &fresh)?;
    replacement.finish().await?;
    Ok(count)
}
async fn ownership_case(stage: &str, mode: &str) -> Result<()> {
    let dir = Directory(std::env::temp_dir().join(format!("dkls-owned-native-{:?}", fresh())));
    provision(&dir.0, 11)?;
    let probe = dir.0.join("actors");
    fs::create_dir(&probe)?;
    let mut actors = Actors::start_variant(&probe, &dir.0, stage, false, None).await?;
    if mode == "incident" {
        actors.expect_publication(1);
    }
    let ready = prepare(&mut actors, [7; 32]).await?;
    let pids = actors
        .group
        .children
        .iter()
        .map(|c| c.id().unwrap())
        .collect::<Vec<_>>();
    let cutoff = tokio::spawn({
        let root = dir.0.clone();
        let probe = probe.clone();
        let mode = mode.to_owned();
        async move {
            wait_roles(&probe, &[0, 1]).await?;
            if mode == "incident" {
                publish(&root, &probe, 1, "incident").await?;
            } else if mode != "positive" {
                fs::write(probe.join("published"), [])?;
            }
            if mode == "death" {
                for pid in pids {
                    kill(pid)?;
                }
            } else {
                if mode == "cancel" {
                    fs::write(probe.join("cancel"), [])?;
                }
                fs::write(probe.join("resume"), [])?;
            }
            Ok::<_, anyhow::Error>(())
        }
    });
    let frames = sign(&mut actors, &ready).await?;
    cutoff.await??;
    let successful_results = if mode == "positive" {
        verify(&frames, &ready)?
    } else {
        ensure!(
            !frames.iter().any(|(_, f)| matches!(f, Frame::Result(_))),
            "ownership interruption released a result"
        );
        0
    };
    finish_except(actors, if mode == "death" { &[0, 1] } else { &[] }).await?;
    retired(&dir.0, &ready)?;
    let log = handoffs(&probe)?;
    let late = log.iter().filter(|v| v["late"] == true).count();
    ensure!(late == 0, "handoff after ownership cutoff");
    let native = log
        .iter()
        .filter(|v| v["kind"] == "native" || v["kind"] == "result")
        .count();
    ensure!(
        if mode == "positive" {
            native > 0
        } else {
            native == 0
        },
        "unexpected native release before constructor/first-native boundary"
    );
    let recovered = if mode == "incident" {
        for role in 0..2 {
            ensure!(
                ReleaseGate::new(
                    pair_scope_dir(
                        &dir.0.join("controls"),
                        ready.request.manifest.identities,
                        1
                    ),
                    role
                )
                .release(|| Ok(()))
                .is_err(),
                "incident not retained"
            );
        }
        0
    } else if mode == "positive" {
        0
    } else {
        replace_and_sign(&dir.0, &ready, "replacement").await?
    };
    evidence(
        &format!("owned-{stage}-{mode}"),
        serde_json::json!({"stage":stage,"mode":mode,"real_preprocessing":true,"both_reservations_irreversibly_retired":true,"duplicate_reservation_refused":true,"observed_native_handoffs":native,"observed_sensitive_handoffs_after_cutoff":late,"positive_verified_result_frames":successful_results,"fresh_replacement_verified_result_frames":recovered,"passed":true}),
    )?;
    fs::write(dir.0.join("passed"), [])?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_pooled_ownership_after_reservation_and_construction_refuses_reuse_and_release() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["reserved", "constructed", "first-native"] {
        for mode in if stage == "first-native" {
            vec!["incident", "death", "positive"]
        } else {
            vec!["incident", "cancel", "death", "positive"]
        } {
            tokio::time::timeout(Duration::from_secs(35), ownership_case(stage, mode))
                .await
                .unwrap()
                .unwrap();
        }
    }
}

async fn one_sided_case(stage: &str, after_release: bool, victim: usize) -> Result<()> {
    let dir = Directory(std::env::temp_dir().join(format!("dkls-one-sided-{:?}", fresh())));
    provision(&dir.0, 11)?;
    let probe = dir.0.join("actors");
    fs::create_dir(&probe)?;
    let mut actors =
        Actors::start_options(&probe, &dir.0, stage, false, None, Some(victim as u8)).await?;
    let (record, hellos) = actors.describe([7; 32]).await?;
    let mut old_sign = None;
    let ops = if stage == "endorsement" {
        std::array::from_fn(|_| Operation::Register {
            record: Box::new(record.clone()),
            hellos: Box::new(hellos.clone()),
        })
    } else if stage == "commit" {
        let w = wallet(record.clone(), actors.endorse(&record, &hellos).await?)?;
        std::array::from_fn(|_| Operation::CommitWallet(Box::new(w.clone())))
    } else {
        let ready = prepare(&mut actors, [7; 32]).await?;
        let c = ready.consumption.clone().unwrap();
        let r = ready.request.clone();
        old_sign = Some(ready);
        std::array::from_fn(|_| Operation::Sign {
            request: Box::new(r.clone()),
            consumption: c.clone(),
        })
    };
    let pid = actors.group.children[victim].id().unwrap();
    let interruption = tokio::spawn({
        let probe = probe.clone();
        async move {
            wait_roles(&probe, &[victim]).await?;
            ensure!(
                !probe.join(format!("{victim}.queued")).exists(),
                "victim already queued"
            );
            if after_release {
                fs::write(probe.join("resume"), [])?;
            } else {
                kill(pid)?;
            }
            Ok::<_, anyhow::Error>(())
        }
    });
    let replies = actors.call(ops).await?;
    interruption.await??;
    let completed_result = replies
        .iter()
        .any(|(_, frame)| matches!(frame, Frame::Result(_)));
    let mut released_wallet = None;
    if after_release {
        if stage == "endorsement" {
            released_wallet = Some(wallet(record.clone(), replies)?);
        } else {
            commit_ack_roles(&replies, record.digest())?;
        }
        kill(pid)?;
    } else {
        ensure!(
            !replies.iter().any(|(role, f)| *role == victim
                && matches!(
                    f,
                    Frame::WalletEndorsement(_) | Frame::WalletRegistered(_) | Frame::Result(_)
                )),
            "killed role released target"
        );
    }
    finish_except(actors, &[victim]).await?;
    ensure!(
        probe.join(format!("{}.done", 1 - victim)).exists(),
        "survivor did not finish"
    );
    let queued = probe.join(format!("{victim}.queued")).exists();
    ensure!(queued == after_release, "victim queue observation");
    if let Some(old) = &old_sign {
        ensure!(
            !completed_result,
            "one-sided signing interruption released a completed result"
        );
        retired(&dir.0, old)?;
    }
    // Both new boot generations are enrolled after the survivor exits; we never
    // attach a replacement to an old pool's boot-bound peer generation.
    let prefix = super::super::hex(&record.manifest.key_id);
    let journals = (0..2)
        .map(|role| {
            fs::read(
                dir.0
                    .join("controls/wallets")
                    .join(format!("{prefix}-{role}.prepared")),
            )
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let committed = fs::read(
        dir.0
            .join("controls/wallets")
            .join(format!("{prefix}.wallet")),
    )
    .ok();
    let replacement_probe = dir.0.join("replacement");
    fs::create_dir(&replacement_probe)?;
    let mut replacement =
        Actors::start_variant(&replacement_probe, &dir.0, "", false, None).await?;
    let fresh = prepare(&mut replacement, [7; 32]).await?;
    ensure!(
        fresh.request.manifest == record.manifest
            && fresh.request.wallet_record == Some(record.digest()),
        "one-sided recovery changed wallet"
    );
    for (role, bytes) in journals.iter().enumerate() {
        ensure!(
            fs::read(
                dir.0
                    .join("controls/wallets")
                    .join(format!("{prefix}-{role}.prepared"))
            )? == *bytes,
            "one-sided recovery changed prepared endorsement"
        );
        if stage == "endorsement" && after_release {
            let saved: serde_json::Value = serde_json::from_slice(bytes)?;
            let wallet: RegisteredWallet = serde_json::from_slice(&fs::read(
                dir.0
                    .join("controls/wallets")
                    .join(format!("{prefix}.wallet")),
            )?)?;
            ensure!(
                serde_json::to_value(&released_wallet.as_ref().unwrap().endorsements[role])?
                    == saved["endorsement"]
                    && wallet.endorsements[role]
                        == released_wallet.as_ref().unwrap().endorsements[role],
                "recovered endorsement mismatch"
            );
        }
    }
    if let Some(bytes) = committed {
        ensure!(
            fs::read(
                dir.0
                    .join("controls/wallets")
                    .join(format!("{prefix}.wallet"))
            )? == bytes,
            "one-sided recovery rewrote committed record"
        );
    }
    if let Some(old) = old_sign {
        ensure!(
            fresh.request.entry != old.request.entry
                && fresh.request.attempt != old.request.attempt,
            "recovery reused old attempt"
        );
    }
    let frames = sign(&mut replacement, &fresh).await?;
    let recovered_results = verify(&frames, &fresh)?;
    replacement.finish().await?;
    evidence(
        &format!("one-sided-{stage}-{after_release}-{victim}"),
        serde_json::json!({"stage":stage,"death_after_release":after_release,"killed_role":victim,"survivor_finished_successfully":true,"victim_target_observed":queued,"exact_journals_preserved":true,"fresh_replacement_verified_result_frames":recovered_results,"passed":true}),
    )?;
    fs::write(dir.0.join("passed"), [])?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_sided_registration_and_signing_death_reuses_exact_wallet_and_fresh_material() {
    let _slot = crate::process_probe::native_fixture_slot().await;
    for stage in ["endorsement", "commit", "consume", "r4"] {
        for after in if matches!(stage, "endorsement" | "commit") {
            vec![false, true]
        } else {
            vec![false]
        } {
            for victim in 0..2 {
                tokio::time::timeout(
                    Duration::from_secs(35),
                    one_sided_case(stage, after, victim),
                )
                .await
                .unwrap()
                .unwrap();
            }
        }
    }
}
