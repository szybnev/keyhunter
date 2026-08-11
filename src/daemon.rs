//! Hourly autonomous scheduler. Persistent state is held in SQLite, not in the container layer.
use anyhow::Result;
use tokio::time::{sleep, Duration};

use crate::{config::Config, scanner::Scanner, storage::Store, verifier::Verifier};

pub async fn run(config: Config, verbose: bool) -> Result<()> {
    let store = Store::open(&config.storage.database_path)?;
    loop {
        if let Err(error) = run_once(&store, &config, verbose).await {
            eprintln!("Autonomous run failed: {error:#}");
        }
        sleep(Duration::from_secs(
            config.daemon.interval_minutes.saturating_mul(60),
        ))
        .await;
    }
}

async fn run_once(store: &Store, config: &Config, verbose: bool) -> Result<()> {
    let provider = store.next_provider(&config.enabled_providers())?;
    let run_id = store.start_run(&provider)?;
    let scanner = Scanner::new(config.clone(), verbose).await?;
    match scanner.scan_sources(&provider, "table", true).await {
        Ok(findings) => {
            let new_findings = store.upsert_findings(&findings)?;
            if config.daemon.verify_new && !new_findings.is_empty() {
                let verifier = Verifier::new(5)?;
                store.save_verifications(&verifier.verify_all(new_findings).await)?;
            }
            store.cleanup(config.storage.retention_days)?;
            store.finish_run(run_id, findings.len(), None)?;
            println!(
                "Autonomous run completed: provider={provider}, findings={}",
                findings.len()
            );
            Ok(())
        }
        Err(error) => {
            store.finish_run(run_id, 0, Some(&error.to_string()))?;
            Err(error)
        }
    }
}
