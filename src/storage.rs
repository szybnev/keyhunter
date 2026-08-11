//! Durable storage for autonomous scans. The database must be kept on a protected volume.

use anyhow::Result;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::scanner::KeyFinding;
use crate::verifier::VerifiedKey;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS runs (
               id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
               status TEXT NOT NULL, source_provider TEXT, findings INTEGER NOT NULL DEFAULT 0,
               error TEXT
             );
             CREATE TABLE IF NOT EXISTS findings (
               id INTEGER PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, provider TEXT NOT NULL,
               key_full TEXT NOT NULL, key_masked TEXT NOT NULL, first_seen TEXT NOT NULL,
               last_seen TEXT NOT NULL, verified INTEGER, verified_at TEXT, verification_error TEXT
             );
             CREATE TABLE IF NOT EXISTS occurrences (
               id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
               source TEXT NOT NULL, repo_name TEXT NOT NULL, repo_url TEXT NOT NULL,
               file_path TEXT NOT NULL, file_url TEXT NOT NULL, owner TEXT NOT NULL,
               first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
               UNIQUE(finding_id, source, repo_name, file_path)
             );
             CREATE TABLE IF NOT EXISTS scheduler_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        )?;
        Ok(Self { conn })
    }

    pub fn start_run(&self, provider: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO runs (started_at,status,source_provider) VALUES (?1,'running',?2)",
            params![Utc::now().to_rfc3339(), provider],
        )?;
        Ok(self.conn.last_insert_rowid())
    }
    pub fn finish_run(&self, id: i64, findings: usize, error: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET finished_at=?1,status=?2,findings=?3,error=?4 WHERE id=?5",
            params![
                Utc::now().to_rfc3339(),
                if error.is_some() {
                    "failed"
                } else {
                    "completed"
                },
                findings as i64,
                error,
                id
            ],
        )?;
        Ok(())
    }
    pub fn next_provider(&self, providers: &[&str]) -> Result<String> {
        let current: usize = self
            .conn
            .query_row(
                "SELECT value FROM scheduler_state WHERE key='provider_index'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let provider = providers
            .get(current % providers.len())
            .ok_or_else(|| anyhow::anyhow!("no enabled providers"))?
            .to_string();
        self.conn.execute("INSERT INTO scheduler_state(key,value) VALUES ('provider_index',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![((current + 1) % providers.len()).to_string()])?;
        Ok(provider)
    }
    pub fn upsert_findings(&self, findings: &[KeyFinding]) -> Result<Vec<KeyFinding>> {
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.unchecked_transaction()?;
        let mut newly_seen = Vec::new();
        for finding in findings {
            let hash = format!("{:x}", Sha256::digest(finding.key.as_bytes()));
            let existed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM findings WHERE key_hash=?1)",
                [&hash],
                |r| r.get(0),
            )?;
            tx.execute("INSERT INTO findings(key_hash,provider,key_full,key_masked,first_seen,last_seen) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(key_hash) DO UPDATE SET last_seen=excluded.last_seen, provider=excluded.provider", params![hash, finding.provider, finding.key, finding.key_masked, now])?;
            let id: i64 =
                tx.query_row("SELECT id FROM findings WHERE key_hash=?1", [&hash], |r| {
                    r.get(0)
                })?;
            tx.execute("INSERT INTO occurrences(finding_id,source,repo_name,repo_url,file_path,file_url,owner,first_seen,last_seen) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8) ON CONFLICT(finding_id,source,repo_name,file_path) DO UPDATE SET last_seen=excluded.last_seen,file_url=excluded.file_url", params![id, finding.source, finding.repo_name, finding.repo_url, finding.file_path, finding.file_url, finding.owner, now])?;
            if !existed {
                newly_seen.push(finding.clone());
            }
        }
        tx.commit()?;
        Ok(newly_seen)
    }
    pub fn save_verifications(&self, verified: &[VerifiedKey]) -> Result<()> {
        for item in verified {
            let hash = format!("{:x}", Sha256::digest(item.finding.key.as_bytes()));
            self.conn.execute("UPDATE findings SET verified=?1,verified_at=?2,verification_error=?3 WHERE key_hash=?4", params![item.is_active as i64, item.verified_at, item.error_message, hash])?;
        }
        Ok(())
    }
    pub fn cleanup(&self, retention_days: i64) -> Result<()> {
        let cutoff = (Utc::now() - Duration::days(retention_days)).to_rfc3339();
        self.conn
            .execute("DELETE FROM occurrences WHERE last_seen < ?1", [&cutoff])?;
        self.conn
            .execute("DELETE FROM findings WHERE last_seen < ?1", [&cutoff])?;
        self.conn.execute(
            "DELETE FROM runs WHERE COALESCE(finished_at,started_at) < ?1",
            [&cutoff],
        )?;
        Ok(())
    }
}
