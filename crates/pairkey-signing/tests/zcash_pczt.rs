#![cfg(feature = "zcash-pczt-tests")]

use orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    keys::{FullViewingKey, Scope, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Anchor,
};
use pairkey_signing::redpallas;
use pairkey_signing::zcash_pczt::{commitment, Network, Spend};
use pairkey_types::{AccountPath, Namespace, Role, Scheme};
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding, PcztResult};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{
    consensus::BlockHeight,
    local_consensus::LocalNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};

fn fixture() -> (Spend, Vec<u8>, Vec<u8>, SpendingKey) {
    let sk = SpendingKey::from_bytes([9; 32]).unwrap();
    let (approval, pczt, ak) = build_fixture(FullViewingKey::from(&sk));
    (approval, pczt, ak, sk)
}

fn build_fixture(fvk: FullViewingKey) -> (Spend, Vec<u8>, Vec<u8>) {
    let mut rng = UnwrapErr(SysRng);
    let recipient = fvk.address_at(0u32, Scope::External);
    let mut builder = OrchardBuilder::new(
        BundleType::UNPADDED,
        orchard::bundle::BundleVersion::ironwood_v3(),
        orchard::bundle::BundleVersion::ironwood_v3().default_flags(),
        Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(1_000_000),
            Memo::Empty.encode().into_bytes(),
        )
        .unwrap();
    let (bundle, meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let action = &bundle.actions()[meta.output_action_index(0).unwrap()];
    let domain = IronwoodDomain::for_action(action);
    let (note, _, _) =
        try_note_decryption(&domain, &fvk.to_ivk(Scope::External).prepare(), action).unwrap();
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let path = MerklePath::from_parts(0, [leaf; 32]);
    let anchor = path.root(cmx);
    let network = LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: Some(BlockHeight::from_u32(10)),
        nu7: None,
    };
    let mut tx = Builder::new(
        network,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::UNPADDED,
        },
    );
    tx.add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, path)
        .unwrap();
    tx.add_ironwood_output::<zip317::FeeRule>(
        Some(fvk.to_ovk(Scope::External)),
        recipient,
        Zatoshis::const_from_u64(990_000),
        MemoBytes::empty(),
    )
    .unwrap();
    let PcztResult { pczt_parts, .. } = tx
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();
    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
        .unwrap()
        .serialize()
        .unwrap();
    let expiry_height = *pczt::Pczt::parse(&pczt).unwrap().global().expiry_height();
    let approval = Spend {
        network: Network::Testnet,
        pczt_hash: commitment(&pczt).unwrap(),
        pczt_len: pczt.len() as u32,
        fvk: fvk.to_bytes().to_vec(),
        recipient: recipient.to_raw_address_bytes().to_vec(),
        output_value_zats: 990_000,
        max_fee_zats: 10_000,
        expiry_height,
    };
    let ak = fvk.to_bytes()[..32].to_vec();
    (approval, pczt, ak)
}

#[test]
fn signs_ironwood_pczt_with_exact_output_and_fee() {
    let (approval, pczt, ak, sk) = fixture();
    let sighash = approval.sighash(&pczt, &ak).unwrap();
    assert_ne!(approval.alpha(&pczt, &ak).unwrap(), [0; 32]);
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
    let signature = approval_signature(&pczt, &ask);
    let signed = approval.signed(&pczt, &ak, &signature).unwrap();
    let parsed = pczt::Pczt::parse(&signed).unwrap();
    assert!(parsed.ironwood().actions()[0]
        .spend()
        .spend_auth_sig()
        .is_some());
    assert_ne!(sighash, [0; 32]);
    assert!(approval.sighash(&signed, &ak).is_err());
    assert!(approval.signed(&pczt, &ak, &[0; 64]).is_err());
}

fn approval_signature(pczt_bytes: &[u8], ask: &orchard::keys::SpendAuthorizingKey) -> [u8; 64] {
    let pczt = pczt::Pczt::parse(pczt_bytes).unwrap();
    let mut signer = pczt::roles::signer::Signer::new(pczt).unwrap();
    signer.sign_ironwood(UnwrapErr(SysRng), 0, ask).unwrap();
    *signer.finish().ironwood().actions()[0]
        .spend()
        .spend_auth_sig()
        .as_ref()
        .unwrap()
}

#[test]
fn rejects_modified_attachment_and_output_policy() {
    let (mut approval, pczt, ak, _) = fixture();
    let mut tampered = pczt.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(approval.sighash(&tampered, &ak).is_err());
    approval.recipient[0] ^= 1;
    assert!(approval.sighash(&pczt, &ak).is_err());
    approval.recipient[0] ^= 1;
    approval.max_fee_zats -= 1;
    assert!(approval.sighash(&pczt, &ak).is_err());
    approval.max_fee_zats += 1;
    approval.network = Network::Mainnet;
    assert!(approval.sighash(&pczt, &ak).is_err());
}

#[test]
fn pairkey_two_party_shares_sign_a_real_pczt() {
    let ns = Namespace {
        version: 1,
        scheme: Scheme::FrostEd25519,
        network: [1; 32],
        registry: [2; 32],
        derivation_authority: [3; 32],
        namespace_id: [4; 32],
        enclave_set: [5; 32],
    };
    let reg = pairkey_frost::register(
        ns.clone(),
        &pairkey_frost::prove(
            &pairkey_frost::Root::new([7; 32]),
            &ns,
            Role::A,
            &mut rand_core::OsRng,
        )
        .unwrap(),
        &pairkey_frost::prove(
            &pairkey_frost::Root::new([8; 32]),
            &ns,
            Role::B,
            &mut rand_core::OsRng,
        )
        .unwrap(),
    )
    .unwrap();
    let path = AccountPath {
        destination: [9; 32],
        path: vec![1],
    };
    let public = redpallas::Public {
        proofs: [
            redpallas::proof(&[11; 32], &reg, &path, Role::A).unwrap(),
            redpallas::proof(&[12; 32], &reg, &path, Role::B).unwrap(),
        ],
    };
    let key = public.key(&reg, &path).unwrap();
    let mut fvk_bytes = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).to_bytes();
    fvk_bytes[..32].copy_from_slice(&redpallas::orchard_ak(&key.public_key).unwrap());
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).unwrap();
    let (approval, pczt, _) = build_fixture(fvk);
    let sighash = approval.sighash(&pczt, &key.public_key).unwrap();
    let alpha = approval.alpha(&pczt, &key.public_key).unwrap();
    let (round_a, pending_a) = redpallas::Pending::begin_orchard(
        &[11; 32],
        &reg,
        &path,
        &public,
        Role::A,
        &sighash,
        &alpha,
    )
    .unwrap();
    let (round_b, pending_b) = redpallas::Pending::begin_orchard(
        &[12; 32],
        &reg,
        &path,
        &public,
        Role::B,
        &sighash,
        &alpha,
    )
    .unwrap();
    let rounds = [round_a, round_b];
    let shares = [
        pending_a.finish(&rounds).unwrap(),
        pending_b.finish(&rounds).unwrap(),
    ];
    let signature =
        redpallas::aggregate_orchard(&reg, &path, &public, &sighash, &alpha, &rounds, &shares)
            .unwrap();
    let signed = approval.signed(&pczt, &key.public_key, &signature).unwrap();
    assert!(pczt::Pczt::parse(&signed).unwrap().ironwood().actions()[0]
        .spend()
        .spend_auth_sig()
        .is_some());
}
