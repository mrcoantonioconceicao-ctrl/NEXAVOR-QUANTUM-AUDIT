use anyhow::Result;
use rustshield_domain::{Dependency, Vulnerability};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvPackageQuery>,
}

#[derive(Debug, Serialize)]
struct OsvPackageQuery {
    package: OsvPackageInfo,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackageInfo {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResultItem>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResultItem {
    #[serde(default)]
    vulns: Vec<OsvVulnItem>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnItem {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cvss: Option<f32>,
}

pub struct OsvClient {
    http_client: reqwest::Client,
    base_url: String,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OsvClient {
    #[must_use]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            http_client: client,
            base_url: "https://api.osv.dev/v1/querybatch".to_string(),
        }
    }

    /// Consulta vulnerabilidades de dependências em lote na base de dados OSV.dev com retries e bounds checking
    pub async fn query_batch_vulnerabilities(&self, dependencies: &[Dependency]) -> Result<Vec<Vulnerability>> {
        if dependencies.is_empty() {
            return Ok(Vec::new());
        }

        let queries = dependencies
            .iter()
            .map(|dep| OsvPackageQuery {
                package: OsvPackageInfo {
                    name: dep.name.clone(),
                    ecosystem: match dep.ecosystem {
                        rustshield_domain::Ecosystem::Cargo => "crates.io".to_string(),
                        rustshield_domain::Ecosystem::Npm => "npm".to_string(),
                        rustshield_domain::Ecosystem::Pip => "PyPI".to_string(),
                        rustshield_domain::Ecosystem::GoMod => "Go".to_string(),
                        rustshield_domain::Ecosystem::Maven => "Maven".to_string(),
                        rustshield_domain::Ecosystem::Other(ref e) => e.clone(),
                    },
                },
                version: dep.version.clone(),
            })
            .collect();

        let request_payload = OsvBatchQuery { queries };

        // Resilient retry loop with exponential backoff and jitter (ETAPA 3)
        let max_retries = 3;
        let mut attempt = 0;
        let mut last_error = None;

        while attempt < max_retries {
            attempt += 1;
            match self.http_client.post(&self.base_url).json(&request_payload).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        match resp.json::<OsvBatchResponse>().await {
                            Ok(parsed) => {
                                let mut results = Vec::new();

                                for (idx, item) in parsed.results.into_iter().enumerate() {
                                    // BOUNDS CHECKING: Proteção estrita contra IndexOutOfBounds
                                    let Some(dep) = dependencies.get(idx) else {
                                        break;
                                    };
                                    for osv_vuln in item.vulns {
                                        let cvss = osv_vuln
                                            .database_specific
                                            .as_ref()
                                            .and_then(|d| d.cvss)
                                            .unwrap_or(7.5);

                                        let title = osv_vuln
                                            .summary
                                            .unwrap_or_else(|| format!("Vulnerabilidade na dependência {}", dep.name));
                                        let desc = osv_vuln.details.unwrap_or_else(|| {
                                            format!("Vulnerabilidade reportada no pacote {} v{}", dep.name, dep.version)
                                        });

                                        if let Ok(v) = Vulnerability::new(
                                            &osv_vuln.id,
                                            cvss,
                                            &title,
                                            &desc,
                                            &format!("dependencies/{}", dep.name),
                                            "OWASP A06:2021-Vulnerable and Outdated Components",
                                        ) {
                                            results.push(v);
                                        }
                                    }
                                }

                                return Ok(results);
                            }
                            Err(e) => {
                                tracing::warn!("Falha ao desserializar resposta do OSV.dev: {e}");
                                return Ok(Vec::new());
                            }
                        }
                    } else if status.as_u16() == 429 || status.is_server_error() {
                        // Rate-limited ou erro transitório de servidor: backoff exponencial com jitter
                        let backoff_ms = (100 * (1 << attempt)) + (attempt * 37) % 50;
                        tracing::warn!(
                            "OSV.dev API retornou status {}. Tentativa {}/{} com backoff de {}ms",
                            status, attempt, max_retries, backoff_ms
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        continue;
                    } else {
                        tracing::warn!("OSV.dev batch API retornou status não recuperável: {}", status);
                        return Ok(Vec::new());
                    }
                }
                Err(err) => {
                    tracing::warn!("Falha de conexão com OSV.dev (tentativa {}/{}): {}", attempt, max_retries, err);
                    last_error = Some(err);
                    let backoff_ms = (150 * (1 << attempt)) + (attempt * 41) % 60;
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                }
            }
        }

        if let Some(e) = last_error {
            tracing::error!("Esgotadas tentativas de conexão com OSV.dev: {e}");
        }

        Ok(Vec::new())
    }
}
