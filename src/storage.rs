//! Durable storage for autonomous scans. The database must be kept on a protected volume.

use anyhow::Result;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::scanner::KeyFinding;
use crate::verifier::VerifiedKey;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredOccurrence {
    pub source: String,
    pub repo_name: String,
    pub repo_url: String,
    pub file_path: String,
    pub file_url: String,
    pub owner: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredFinding {
    pub provider: String,
    pub key: String,
    pub key_masked: String,
    pub first_seen: String,
    pub last_seen: String,
    pub verified: Option<bool>,
    pub verified_at: Option<String>,
    pub verification_error: Option<String>,
    pub locations: Vec<StoredOccurrence>,
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

    /// Opens an existing database without creating files or applying migrations.
    pub fn open_readonly(path: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    /// Lists persisted findings and their source locations without modifying storage.
    pub fn list_findings(&self, status: &str) -> Result<Vec<StoredFinding>> {
        let predicate = match status {
            "active" => "verified = 1",
            "inactive" => "verified = 0",
            "unverified" => "verified IS NULL",
            "all" => "1 = 1",
            _ => {
                anyhow::bail!("Invalid status '{status}'. Use active, inactive, unverified, or all")
            }
        };
        let sql = format!(
            "SELECT id, provider, key_full, key_masked, first_seen, last_seen, verified, verified_at, verification_error \
             FROM findings WHERE {predicate} ORDER BY last_seen DESC, id DESC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                StoredFinding {
                    provider: row.get(1)?,
                    key: row.get(2)?,
                    key_masked: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    verified: row.get::<_, Option<i64>>(6)?.map(|value| value != 0),
                    verified_at: row.get(7)?,
                    verification_error: row.get(8)?,
                    locations: Vec::new(),
                },
            ))
        })?;
        let mut findings = Vec::new();
        for row in rows {
            let (id, mut finding) = row?;
            let mut locations = self.conn.prepare(
                "SELECT source, repo_name, repo_url, file_path, file_url, owner, first_seen, last_seen \
                 FROM occurrences WHERE finding_id = ?1 ORDER BY last_seen DESC, id DESC",
            )?;
            finding.locations = locations
                .query_map([id], |row| {
                    Ok(StoredOccurrence {
                        source: row.get(0)?,
                        repo_name: row.get(1)?,
                        repo_url: row.get(2)?,
                        file_path: row.get(3)?,
                        file_url: row.get(4)?,
                        owner: row.get(5)?,
                        first_seen: row.get(6)?,
                        last_seen: row.get(7)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            findings.push(finding);
        }
        Ok(findings)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::KeyFinding;

    fn finding(key: &str, path: &str) -> KeyFinding {
        KeyFinding {
            source: "github".to_string(),
            provider: "openai".to_string(),
            key: key.to_string(),
            key_masked: "sk-...test".to_string(),
            file_path: path.to_string(),
            file_url: format!("https://example.test/{path}"),
            repo_name: "owner/repo".to_string(),
            repo_url: "https://example.test/owner/repo".to_string(),
            owner: "owner".to_string(),
            owner_url: "https://example.test/owner".to_string(),
            owner_type: "User".to_string(),
            found_at: Utc::now().to_rfc3339(),
            verified: None,
        }
    }

    #[test]
    fn list_findings_filters_status_and_groups_locations() {
        let path =
            std::env::temp_dir().join(format!("keyhunter-store-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(path.to_str().unwrap()).unwrap();
        let first = finding("sk-test-key", ".env");
        let second = finding("sk-test-key", "config.toml");
        store.upsert_findings(&[first.clone(), second]).unwrap();
        let verified = VerifiedKey {
            finding: first,
            is_active: true,
            verified_at: Utc::now().to_rfc3339(),
            verification_method: "test".to_string(),
            error_message: None,
        };
        store.save_verifications(&[verified]).unwrap();

        let active = store.list_findings("active").unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].locations.len(), 2);
        assert!(store.list_findings("inactive").unwrap().is_empty());
        assert!(store.list_findings("unverified").unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
