#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: pairkey-coordinator CONFIG_FILE"))?;
    let config = serde_json::from_slice(&std::fs::read(path)?)?;
    pairkey_coordinator::run(config).await
}
