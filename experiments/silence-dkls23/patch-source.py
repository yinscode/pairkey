"""Apply the documented constructor, ID fix, abort preservation and gated fixture."""
from pathlib import Path
import sys
import tarfile

source, experiment = map(Path, sys.argv[1:])
keyshare = source / "src/keygen/keyshare.rs"
marker = '\ninclude!("pairkey_research.rs");\n'
old = "party_idx_to_id_map.windows(2).all(|w| w[0] != w[1])"
new = "party_idx_to_id_map.windows(2).all(|w| w[0].1 != w[1].1)"
fault_old = b"""                let x_i = &x_i_list[receiver_id as usize];"""
fault_new = b"""                #[cfg(feature = "pairkey-research-faults")]
                if std::env::var("PAIRKEY_RESEARCH_BAD_MIGRATION_PPRF").as_deref() == Ok("1") {
                    bytemuck::bytes_of_mut(&mut msg3.pprf_output)[192] ^= 1;
                }
                let x_i = &x_i_list[receiver_id as usize];"""
with tarfile.open(source.parent / "dkls23.tar.gz") as archive:
    prefix = source.name + "/"
    for member in archive.getmembers():
        if not member.isfile() or not member.name.startswith(prefix):
            continue
        relative = member.name[len(prefix):]
        if not (relative.endswith(".rs") or relative.endswith("Cargo.toml") or relative == "LICENSE"):
            continue
        original = archive.extractfile(member).read()
        expected = original
        if relative == "src/keygen/keyshare.rs":
            expected = original.replace(b"impl Keyshare {\n", (marker + "\nimpl Keyshare {\n").encode(), 1)
        elif relative == "src/sign/dsg.rs":
            if old.encode() not in original:
                raise SystemExit("Unexpected pinned participant-ID validation")
            expected = original.replace(old.encode(), new.encode(), 1)
        elif relative == "src/keygen/migration.rs":
            abort_send = b"            relay.send(abort_msg).await?;"
            if original.count(abort_send) != 1:
                raise SystemExit("Unexpected migration abort path")
            expected = original.replace(abort_send, b"""            // Abort delivery is best effort. Preserve the authenticated
            // protocol violation even when the transport also fails.
            // The research relay records abort-send failure separately.
            let _ = relay.send(abort_msg).await;""", 1)
        elif relative == "src/keygen/dkg.rs":
            if fault_old not in original: raise SystemExit("Unexpected migration fault location")
            expected = original.replace(fault_old, fault_new, 1)
        elif relative == "Cargo.toml":
            expected = original.replace(b"[features]", b"[features]\npairkey-research-faults = []", 1)
        target = source / relative
        current = target.read_bytes()
        if current not in (original, expected):
            raise SystemExit(f"Unexpected change in pinned research source: {relative}")
        if current != expected:
            target.write_bytes(expected)
adapter = source / "src/keygen/pairkey_research.rs"
adapter_bytes = (experiment / "patches/research-keyshare.rs").read_bytes()
if not adapter.exists() or adapter.read_bytes() != adapter_bytes:
    adapter.write_bytes(adapter_bytes)
