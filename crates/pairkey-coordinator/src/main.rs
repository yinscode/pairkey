#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: pairkey-coordinator CONFIG_FILE"))?;
    let mut config: pairkey_coordinator::Config = serde_json::from_slice(&std::fs::read(&path)?)?;
    if config.jobs_file.is_none() {
        config.jobs_file = Some(format!("{path}.jobs.json"));
    }
    pairkey_coordinator::run(config).await
}
