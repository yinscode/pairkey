#[cfg(feature = "dev-simulation")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: pairkey-worker CONFIG_FILE"))?;
    pairkey_worker::development::run(&path).await
}
#[cfg(not(feature = "dev-simulation"))]
fn main() {
    eprintln!(
        "No production provisioner is installed. Local use requires --features dev-simulation."
    );
    std::process::exit(1);
}
