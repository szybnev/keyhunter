//! Minimal GitLab.com code-search client. GitLab may reject blob search when unavailable.
use anyhow::{Context, Result};
use reqwest::{header, Client};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

#[derive(Clone)]
pub struct GitLabClient {
    client: Client,
    delay_ms: u64,
    request_count: Arc<AtomicUsize>,
    max_requests: usize,
    semaphore: Arc<Semaphore>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct GitLabItem {
    pub data: String,
    pub path: String,
    pub ref_: Option<String>,
    pub project_id: u64,
}
#[derive(Deserialize)]
struct RawItem {
    data: String,
    path: String,
    #[serde(rename = "ref")]
    ref_: Option<String>,
    project_id: u64,
}
impl GitLabClient {
    pub fn new(
        token: &str,
        concurrency: usize,
        delay_ms: u64,
        max_requests: usize,
    ) -> Result<Self> {
        let mut h = header::HeaderMap::new();
        h.insert("PRIVATE-TOKEN", header::HeaderValue::from_str(token)?);
        h.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("keyhunter/0.1"),
        );
        Ok(Self {
            client: Client::builder()
                .default_headers(h)
                .timeout(Duration::from_secs(30))
                .build()?,
            delay_ms,
            request_count: Arc::new(AtomicUsize::new(0)),
            max_requests,
            semaphore: Arc::new(Semaphore::new(concurrency)),
        })
    }
    pub async fn check_code_search(&self) -> Result<()> {
        self.search_code("keyhunter_capability_probe", 1, 1)
            .await
            .map(|_| ())
    }
    pub async fn search_code(
        &self,
        query: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Vec<GitLabItem>> {
        if self.request_count.fetch_add(1, Ordering::SeqCst) >= self.max_requests {
            anyhow::bail!("GitLab request budget exhausted for this hourly run")
        }
        let _permit = self.semaphore.acquire().await?;
        sleep(Duration::from_millis(self.delay_ms)).await;
        let response = self
            .client
            .get("https://gitlab.com/api/v4/search")
            .query(&[
                ("scope", "blobs"),
                ("search", query),
                ("page", &page.to_string()),
                ("per_page", &per_page.to_string()),
            ])
            .send()
            .await
            .context("GitLab search request failed")?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            anyhow::bail!("Rate limited by GitLab")
        }
        if !response.status().is_success() {
            anyhow::bail!("GitLab code search unavailable: {}", response.status())
        }
        Ok(response
            .json::<Vec<RawItem>>()
            .await?
            .into_iter()
            .map(|x| GitLabItem {
                data: x.data,
                path: x.path,
                ref_: x.ref_,
                project_id: x.project_id,
            })
            .collect())
    }
}
