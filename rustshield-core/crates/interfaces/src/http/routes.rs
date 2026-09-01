use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use rustshield_application::{CalculateRiskUseCase, RefactorEngine, RefactorTargetMode, ScanRepositoryUseCase};
use rustshield_domain::{Repository, SourceFile};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::mcp::{JsonRpcRequest, RustMcpServer};

pub fn create_router() -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/mcp", post(mcp_handler))
        .route("/api/audit/ast-refactor", post(ast_refactor_handler))
        .route("/api/audit/calculate-fair", post(calculate_fair_handler))
}

async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "HEALTHY",
            "engine": "RustShield Secure Core v2.0",
            "runtime": "Native Rust 1.70+ (Axum/Tokio)",
            "memory_safety": "Kernel Level / Zero Trust",
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
}

async fn mcp_handler(Json(payload): Json(JsonRpcRequest)) -> impl IntoResponse {
    let response = RustMcpServer::handle_request(payload);
    (StatusCode::OK, Json(response))
}

#[derive(Debug, Deserialize)]
pub struct AstRefactorRequest {
    #[serde(default)]
    pub file_path: Option<String>,
    pub original_content: String,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub target_mode: Option<String>,
}

async fn ast_refactor_handler(Json(payload): Json<AstRefactorRequest>) -> impl IntoResponse {
    let path = payload.file_path.unwrap_or_else(|| "src/sample.rs".to_string());
    let lang = payload.language.unwrap_or_else(|| "rust".to_string());
    let raw_mode = payload.target_mode.unwrap_or_else(|| "IN_PLACE".to_string());

    let mode = match raw_mode.to_uppercase().as_str() {
        "RUST" => RefactorTargetMode::Rust,
        "GO" => RefactorTargetMode::Go,
        _ => RefactorTargetMode::InPlace,
    };

    match SourceFile::new(&path, &payload.original_content, &lang) {
        Ok(file) => {
            let vulns = rustshield_infrastructure::NativeAstEngine::scan_source_file(&file);
            let result = RefactorEngine::refactor(&file, mode, &vulns);
            (StatusCode::OK, Json(json!(result)))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": e.to_string()
            })),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct CalculateFairRequest {
    pub asset_value_usd: f64,
    pub exposure_factor_percent: f64,
    pub aro: f64,
    pub security_cost_usd: f64,
    pub mitigation_percent: f64,
}

async fn calculate_fair_handler(Json(payload): Json<CalculateFairRequest>) -> impl IntoResponse {
    let eval = CalculateRiskUseCase::execute(
        payload.asset_value_usd,
        payload.exposure_factor_percent,
        payload.aro,
        payload.security_cost_usd,
        payload.mitigation_percent,
    );
    (StatusCode::OK, Json(json!(eval)))
}
