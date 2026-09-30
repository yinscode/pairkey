//! Review-only child module of wire.rs, compiled in a scratch copy.
//! Tests the actual SetupChannel with a crossed in-memory Frame transport.
use super::*;
use pairkey_dkls23_research::pool::{self, Consumption, SetupInput};

fn wire(tx: mpsc::UnboundedSender<Frame>, control: mpsc::UnboundedReceiver<Frame>) -> Wire {
    let (_unused, rx) = mpsc::unbounded_channel();
    Wire { gate: None, abort_watch: None, partial_probe: None, process_probe: None, tx, rx, control }
}

async fn exchange(contexts: [[u8; 32]; 2], labels: [&str; 2]) -> [Result<[u8; 32]>; 2] {
    let secrets = [StaticSecret::from(fresh()), StaticSecret::from(fresh())];
    let c0 = SetupChannel::bound(&secrets[0], PublicKey::from(&secrets[1]).to_bytes(), contexts[0], 0, [1; 32]).unwrap();
    let c1 = SetupChannel::bound(&secrets[1], PublicKey::from(&secrets[0]).to_bytes(), contexts[1], 1, [2; 32]).unwrap();
    let (tx0, rx0) = mpsc::unbounded_channel();
    let (tx1, rx1) = mpsc::unbounded_channel();
    let mut w0 = wire(tx0, rx1);
    let mut w1 = wire(tx1, rx0);
    let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(c0.exchange(&mut w0, labels[0], &contexts[0]), c1.exchange(&mut w1, labels[1], &contexts[1]))
    }).await.expect("channel exchange timed out");
    [a, b]
}

fn rejected_both(outcomes: [Result<[u8; 32]>; 2], field: &str) {
    for outcome in outcomes {
        let error = outcome.expect_err(field);
        let failure = error.downcast_ref::<Failure>().expect("typed context failure");
        assert_eq!(failure.kind, FailureKind::Context, "{field}");
        assert_eq!(failure.action, pairkey_dkls23_research::lifecycle::Action::Burn, "{field}");
    }
}

#[tokio::test]
async fn o4_setup_and_consumption_mutations_fail_before_native_signing() {
    let setup = SetupInput {
        version: 1, recipe: 1, peers: [fresh(), fresh()], boots: [fresh(), fresh()],
        configuration: pool::configuration(), entry: fresh(),
    };
    // Arbitrary identity bytes are sufficient for this channel-boundary test;
    // enrollment validation remains outside it.
    let c = Consumption {
        version: 2, input: setup.digest(), completed: fresh(), entry: setup.entry,
        wallet: fresh(), scheme: "secp256k1/bip32-public".into(), path: "m/7/3".into(),
        prehash: fresh(), receipt: fresh(), policy_version: 1, attempt: fresh(),
    };
    let ok = exchange([c.digest(); 2], ["pool-reservation"; 2]).await;
    for result in ok { assert_eq!(result.unwrap(), c.digest()); }
    let ok = exchange([setup.digest(); 2], ["pool-zero-commit"; 2]).await;
    for result in ok { assert_eq!(result.unwrap(), setup.digest()); }

    let mut checked = 0;
    for field in ["version", "input", "completed", "entry", "wallet", "scheme", "path", "prehash", "receipt", "policy_version", "attempt"] {
        let mut other = c.clone();
        match field {
            "version" => other.version += 1,
            "input" => other.input[0] ^= 1,
            "completed" => other.completed[0] ^= 1,
            "entry" => other.entry[0] ^= 1,
            "wallet" => other.wallet[0] ^= 1,
            "scheme" => other.scheme.push('x'),
            "path" => other.path.push_str("/1"),
            "prehash" => other.prehash[0] ^= 1,
            "receipt" => other.receipt[0] ^= 1,
            "policy_version" => other.policy_version += 1,
            "attempt" => other.attempt[0] ^= 1,
            _ => unreachable!(),
        }
        rejected_both(exchange([c.digest(), other.digest()], ["pool-reservation"; 2]).await, field);
        checked += 1;
    }
    for field in ["version", "recipe", "peer0", "peer1", "boot0", "boot1", "configuration", "entry"] {
        let mut other = setup.clone();
        match field {
            "version" => other.version += 1,
            "recipe" => other.recipe += 1,
            "peer0" => other.peers[0][0] ^= 1,
            "peer1" => other.peers[1][0] ^= 1,
            "boot0" => other.boots[0][0] ^= 1,
            "boot1" => other.boots[1][0] ^= 1,
            "configuration" => other.configuration[0] ^= 1,
            "entry" => other.entry[0] ^= 1,
            _ => unreachable!(),
        }
        rejected_both(exchange([setup.digest(), other.digest()], ["pool-zero-commit"; 2]).await, field);
        checked += 1;
    }
    rejected_both(exchange([setup.digest(); 2], ["pool-zero-commit", "pool-zero-reveal"]).await, "phase");
    checked += 1;
    println!("2 matching-context controls succeeded; {checked} context/phase mutations rejected on both sides with typed Burn/Context errors. No native signing invoked.");
}
