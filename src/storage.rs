//! Durable storage for autonomous scans. The database must be kept on a protected volume.

use anyhow::Result;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::scanner::KeyFinding;
use crate::verifier::{VerificationOutcome, VerifiedKey};

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
    pub ever_valid: bool,
    pub latest_status: String,
    pub last_checked_at: Option<String>,
    pub last_valid_at: Option<String>,
    pub last_invalid_at: Option<String>,
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
        let store = Self { conn };
        store.migrate_verification_state()?;
        Ok(store)
    }

    fn has_column(&self, table: &str, column: &str) -> Result<bool> {
        let mut statement = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(columns.iter().any(|name| name == column))
    }

    /// Idempotent migration for databases created by earlier daemon versions.
    fn migrate_verification_state(&self) -> Result<()> {
        for (column, definition) in [
            ("ever_valid", "INTEGER NOT NULL DEFAULT 0"),
            ("latest_status", "TEXT NOT NULL DEFAULT 'unverified'"),
            ("last_checked_at", "TEXT"),
            ("last_valid_at", "TEXT"),
            ("last_invalid_at", "TEXT"),
            ("next_retry_at", "TEXT"),
        ] {
            if !self.has_column("findings", column)? {
                self.conn.execute_batch(&format!(
                    "ALTER TABLE findings ADD COLUMN {column} {definition}"
                ))?;
            }
        }
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS verification_attempts (
                id INTEGER PRIMARY KEY,
                finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                checked_at TEXT NOT NULL,
                outcome TEXT NOT NULL,
                method TEXT NOT NULL,
                error_message TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_recheck ON findings(latest_status, last_checked_at);
            CREATE INDEX IF NOT EXISTS idx_attempts_finding ON verification_attempts(finding_id, checked_at);",
        )?;
        // Earlier versions did not persist enough response evidence to prove
        // that a false result was an authentication rejection.
        self.conn.execute_batch(
            "UPDATE findings SET
                ever_valid = CASE WHEN verified = 1 THEN 1 ELSE ever_valid END,
                latest_status = CASE
                    WHEN verified = 1 THEN 'valid'
                    WHEN verified = 0 THEN 'indeterminate'
                    ELSE latest_status END,
                last_checked_at = COALESCE(last_checked_at, verified_at),
                last_valid_at = CASE WHEN verified = 1 THEN COALESCE(last_valid_at, verified_at) ELSE last_valid_at END,
                last_invalid_at = last_invalid_at;",
        )?;
        Ok(())
    }

    /// Opens an existing database without creating files or applying migrations.
    pub fn open_readonly(path: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    /// Lists persisted findings and their source locations without modifying storage.
    pub fn list_findings(&self, status: &str) -> Result<Vec<StoredFinding>> {
        let predicate = match status {
            "active" | "valid" => "ever_valid = 1",
            "inactive" | "invalid" => "latest_status = 'invalid'",
            "error" | "indeterminate" => {
                "latest_status IN ('retryable_error', 'indeterminate', 'unsupported')"
            }
            "unverified" => "latest_status = 'unverified'",
            "all" => "1 = 1",
            _ => {
                anyhow::bail!(
                    "Invalid status '{status}'. Use valid, invalid, error, unverified, or all"
                )
            }
        };
        let sql = format!(
            "SELECT id, provider, key_full, key_masked, first_seen, last_seen, verified, verified_at, verification_error, ever_valid, latest_status, last_checked_at, last_valid_at, last_invalid_at \
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
                    ever_valid: row.get::<_, i64>(9)? != 0,
                    latest_status: row.get(10)?,
                    last_checked_at: row.get(11)?,
                    last_valid_at: row.get(12)?,
                    last_invalid_at: row.get(13)?,
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
            let legacy_verified: Option<i64> = match item.outcome {
                VerificationOutcome::Valid => Some(1),
                VerificationOutcome::Invalid => Some(0),
                _ => None,
            };
            let retry_at = if item.outcome == VerificationOutcome::RetryableError {
                Some((Utc::now() + Duration::hours(1)).to_rfc3339())
            } else {
                None
            };
            self.conn.execute(
                "UPDATE findings SET
                    verified=?1, verified_at=?2, verification_error=?3,
                    ever_valid=CASE WHEN ?4 = 'valid' THEN 1 ELSE ever_valid END,
                    latest_status=?4, last_checked_at=?2,
                    last_valid_at=CASE WHEN ?4 = 'valid' THEN ?2 ELSE last_valid_at END,
                    last_invalid_at=CASE WHEN ?4 = 'invalid' THEN ?2 ELSE last_invalid_at END,
                    next_retry_at=?5
                 WHERE key_hash=?6",
                params![
                    legacy_verified,
                    item.verified_at,
                    item.error_message,
                    item.outcome.as_str(),
                    retry_at,
                    hash
                ],
            )?;
            let finding_id: i64 = self.conn.query_row(
                "SELECT id FROM findings WHERE key_hash=?1",
                [&hash],
                |row| row.get(0),
            )?;
            self.conn.execute(
                "INSERT INTO verification_attempts(finding_id,checked_at,outcome,method,error_message) VALUES(?1,?2,?3,?4,?5)",
                params![finding_id, item.verified_at, item.outcome.as_str(), item.verification_method, item.error_message],
            )?;
        }
        Ok(())
    }

    /// Selects only AI/LLM findings due for verification. Other provider types
    /// are intentionally never sent to external APIs by autonomous mode.
    pub fn findings_for_recheck(&self, scope: &str, count: usize) -> Result<Vec<KeyFinding>> {
        let scope_predicate = match scope {
            "valid" => "f.ever_valid = 1",
            "invalid" => "f.latest_status = 'invalid'",
            "all" => "1 = 1",
            _ => anyhow::bail!("Invalid recheck scope '{scope}'. Use valid, invalid, or all"),
        };
        let ai_providers = "'openai','anthropic','google','groq','perplexity','huggingface','replicate','fireworks','cohere','mistral','together','deepseek'";
        let sql = format!(
            "SELECT f.provider,f.key_full,f.key_masked,f.first_seen,o.source,o.file_path,o.file_url,o.repo_name,o.repo_url,o.owner \
             FROM findings f JOIN occurrences o ON o.id=(SELECT id FROM occurrences WHERE finding_id=f.id ORDER BY last_seen DESC,id DESC LIMIT 1) \
             WHERE {scope_predicate} AND f.provider IN ({ai_providers}) AND (f.next_retry_at IS NULL OR f.next_retry_at <= ?1) \
             ORDER BY CASE WHEN f.last_checked_at IS NULL THEN 0 ELSE 1 END, f.last_checked_at ASC, f.id ASC LIMIT ?2"
        );
        let now = Utc::now().to_rfc3339();
        self.conn
            .prepare(&sql)?
            .query_map(params![now, count as i64], |row| {
                let latest: Option<bool> = None;
                Ok(KeyFinding {
                    provider: row.get(0)?,
                    key: row.get(1)?,
                    key_masked: row.get(2)?,
                    found_at: row.get(3)?,
                    source: row.get(4)?,
                    file_path: row.get(5)?,
                    file_url: row.get(6)?,
                    repo_name: row.get(7)?,
                    repo_url: row.get(8)?,
                    owner: row.get(9)?,
                    owner_url: String::new(),
                    owner_type: String::new(),
                    verified: latest,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
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
            outcome: VerificationOutcome::Valid,
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

    #[test]
    fn error_attempt_is_not_classified_as_invalid_and_non_ai_is_not_rechecked() {
        let path = std::env::temp_dir().join(format!(
            "keyhunter-store-outcome-{}-{}.sqlite",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let store = Store::open(path.to_str().unwrap()).unwrap();
        let ai = finding("sk-ai-key", ".env");
        let mut non_ai = finding("AKIAIOSFODNN7EXAMPLE", "aws.env");
        non_ai.provider = "aws".to_string();
        store.upsert_findings(&[ai.clone(), non_ai]).unwrap();
        store
            .save_verifications(&[VerifiedKey {
                finding: ai,
                is_active: false,
                outcome: VerificationOutcome::Indeterminate,
                verified_at: Utc::now().to_rfc3339(),
                verification_method: "GET /v1/models".to_string(),
                error_message: Some("unexpected provider response".to_string()),
            }])
            .unwrap();

        assert!(store.list_findings("invalid").unwrap().is_empty());
        assert_eq!(store.list_findings("error").unwrap().len(), 1);
        let due = store.findings_for_recheck("all", 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].provider, "openai");
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migrates_legacy_error_to_indeterminate() {
        let path = std::env::temp_dir().join(format!(
            "keyhunter-store-migration-{}-{}.sqlite",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE findings (
                    id INTEGER PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, provider TEXT NOT NULL,
                    key_full TEXT NOT NULL, key_masked TEXT NOT NULL, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, verified INTEGER, verified_at TEXT, verification_error TEXT
                );
                INSERT INTO findings(key_hash,provider,key_full,key_masked,first_seen,last_seen,verified,verified_at,verification_error)
                VALUES('hash','openai','sk-test','sk-...test','2020-01-01','2020-01-01',0,'2020-01-01','rate limited');",
            )
            .unwrap();
        drop(connection);

        let store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.list_findings("error").unwrap().len(), 1);
        assert!(store.list_findings("invalid").unwrap().is_empty());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
