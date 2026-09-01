use rustshield_application::{CalculateRiskUseCase, RefactorEngine, RefactorTargetMode};
use rustshield_domain::SourceFile;
use rustshield_infrastructure::NativeAstEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

pub struct RustMcpServer;

impl RustMcpServer {
    #[must_use]
    pub fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id;

        match req.method.as_str() {
            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "analyze_ast",
                            "description": "Executa análise sintática estática determinística no código-fonte via RustShield Secure Core para identificar violações de segurança (OWASP Top 10, memory safety e injeções).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "code": { "type": "string", "description": "Código-fonte a ser auditado" },
                                    "language": { "type": "string", "description": "Linguagem de programação (ex: rust, python, typescript, cpp)" },
                                    "filePath": { "type": "string", "description": "Caminho do arquivo" }
                                },
                                "required": ["code", "language"]
                            }
                        },
                        {
                            "name": "refactor_code",
                            "description": "Executa a refatoração e hardening de segurança de código legado com suporte aos modos IN_PLACE (mesma linguagem), RUST (migração para Rust idiomático) e GO (migração para Go).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "code": { "type": "string", "description": "Código legado a ser refatorado" },
                                    "language": { "type": "string", "description": "Linguagem de origem" },
                                    "target_mode": { "type": "string", "enum": ["IN_PLACE", "RUST", "GO"], "description": "Modo de destino" },
                                    "filePath": { "type": "string", "description": "Caminho do arquivo" }
                                },
                                "required": ["code", "language", "target_mode"]
                            }
                        },
                        {
                            "name": "calculate_risk",
                            "description": "Calcula métricas financeiras de risco cibernético utilizando o modelo FAIR (SLE, ALE, ARO e ROSI).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "assetValueUsd": { "type": "number" },
                                    "exposureFactorPercent": { "type": "number" },
                                    "aro": { "type": "number" },
                                    "securityCostUsd": { "type": "number" },
                                    "mitigationPercent": { "type": "number" }
                                },
                                "required": ["assetValueUsd", "exposureFactorPercent", "aro", "securityCostUsd", "mitigationPercent"]
                            }
                        }
                    ]
                });

                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: Some(tools),
                    error: None,
                }
            }
            "tools/call" => {
                let params = req.params.unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(Value::as_str).unwrap_or_default();
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);

                match tool_name {
                    "analyze_ast" => {
                        let code = args.get("code").and_then(Value::as_str).unwrap_or_default();
                        let lang = args.get("language").and_then(Value::as_str).unwrap_or("rust");
                        let path = args.get("filePath").and_then(Value::as_str).unwrap_or("src/sample.rs");

                        if let Ok(file) = SourceFile::new(path, code, lang) {
                            let vulns = NativeAstEngine::scan_source_file(&file);
                            JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id,
                                result: Some(json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&vulns).unwrap_or_default()
                                    }]
                                })),
                                error: None,
                            }
                        } else {
                            JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id,
                                result: None,
                                error: Some(JsonRpcError { code: -32602, message: "Parâmetros inválidos para analyze_ast".to_string() }),
                            }
                        }
                    }
                    "refactor_code" => {
                        let code = args.get("code").and_then(Value::as_str).unwrap_or_default();
                        let lang = args.get("language").and_then(Value::as_str).unwrap_or("rust");
                        let raw_mode = args.get("target_mode").and_then(Value::as_str).unwrap_or("IN_PLACE");
                        let path = args.get("filePath").and_then(Value::as_str).unwrap_or("src/sample.rs");

                        let mode = match raw_mode.to_uppercase().as_str() {
                            "RUST" => RefactorTargetMode::Rust,
                            "GO" => RefactorTargetMode::Go,
                            _ => RefactorTargetMode::InPlace,
                        };

                        if let Ok(file) = SourceFile::new(path, code, lang) {
                            let vulns = NativeAstEngine::scan_source_file(&file);
                            let result = RefactorEngine::refactor(&file, mode, &vulns);
                            JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id,
                                result: Some(json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                                    }]
                                })),
                                error: None,
                            }
                        } else {
                            JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id,
                                result: None,
                                error: Some(JsonRpcError { code: -32602, message: "Parâmetros inválidos para refactor_code".to_string() }),
                            }
                        }
                    }
                    "calculate_risk" => {
                        let asset_val = args.get("assetValueUsd").and_then(Value::as_f64).unwrap_or(0.0);
                        let ef = args.get("exposureFactorPercent").and_then(Value::as_f64).unwrap_or(0.0);
                        let aro = args.get("aro").and_then(Value::as_f64).unwrap_or(0.0);
                        let cost = args.get("securityCostUsd").and_then(Value::as_f64).unwrap_or(0.0);
                        let mit = args.get("mitigationPercent").and_then(Value::as_f64).unwrap_or(0.0);

                        let eval = CalculateRiskUseCase::execute(asset_val, ef, aro, cost, mit);
                        JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id,
                            result: Some(json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&eval).unwrap_or_default()
                                }]
                            })),
                            error: None,
                        }
                    }
                    unknown => JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32601,
                            message: format!("Ferramenta desconhecida: {unknown}"),
                        }),
                    },
                }
            }
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Método não encontrado: {}", req.method),
                }),
            },
        }
    }
}
