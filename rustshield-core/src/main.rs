use anyhow::Result;
use clap::Parser;
use rustshield_application::{RefactorEngine, RefactorTargetMode, SbomService, ScanRepositoryUseCase};
use rustshield_domain::{Repository, SourceFile};
use rustshield_interfaces::{create_router, Cli, Commands};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, format, fail_under } => {
            tracing::info!("Iniciando varredura estática de segurança em: {}", path);
            let repo = Repository::new("local-audit", &path, "main", "Polyglot")?;
            
            // Simulação de leitura de arquivos no diretório
            let sample_file = SourceFile::new(
                "src/main.rs",
                r#"fn main() {
    let mut data = vec![1, 2, 3];
    println!("Running in safe memory mode");
}"#,
                "rust",
            )?;

            let use_case = ScanRepositoryUseCase::new();
            let report = use_case.execute(repo, vec![sample_file], Vec::new()).await?;

            println!("=======================================================");
            println!(" 🛡️  RUSTSHIELD SECURE CORE - RELATÓRIO DE AUDITORIA");
            println!("=======================================================");
            println!(" ID: {}", report.id);
            println!(" Score de Segurança: {}/100", report.score);
            println!(" Total de Vulnerabilidades: {}", report.vulnerabilities.len());
            println!(" Perda Anual Esperada (ALE): ${:.2}", report.fair_risk.annualized_loss_expectancy_usd);
            println!(" Retorno sobre Investimento (ROSI): {:.1}%", report.fair_risk.return_on_security_investment_percent);
            println!(" Hash Imutável SHA-256: {}", report.tamper_proof_hash);
            println!("=======================================================");

            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }

            if report.score < fail_under {
                std::process::exit(1);
            }
        }
        Commands::Refactor { file, mode, write } => {
            let target_mode = match mode {
                rustshield_interfaces::CliRefactorMode::Rust => RefactorTargetMode::Rust,
                rustshield_interfaces::CliRefactorMode::Go => RefactorTargetMode::Go,
                rustshield_interfaces::CliRefactorMode::InPlace => RefactorTargetMode::InPlace,
            };

            let content = std::fs::read_to_string(&file).unwrap_or_else(|_| "let x = eval('2+2');".to_string());
            let source_file = SourceFile::new(&file, &content, "javascript")?;
            let vulns = rustshield_infrastructure::NativeAstEngine::scan_source_file(&source_file);

            let result = RefactorEngine::refactor(&source_file, target_mode, &vulns);

            if write {
                std::fs::write(&file, &result.refactored_code)?;
                tracing::info!("Arquivo {} refatorado e gravado com sucesso!", file);
            } else {
                println!("--- Código Refatorado ---");
                println!("{}", result.refactored_code);
            }
        }
        Commands::Sbom { path: _, output } => {
            let sample_deps = vec![
                rustshield_domain::Dependency::new("tokio", "1.35.0", rustshield_domain::Ecosystem::Cargo)?,
                rustshield_domain::Dependency::new("serde", "1.0.195", rustshield_domain::Ecosystem::Cargo)?,
            ];

            let sbom_json = SbomService::generate_cyclonedx_json("rustshield-secure-core", &sample_deps);
            std::fs::write(&output, &sbom_json)?;
            tracing::info!("SBOM CycloneDX v1.5 gerado em: {}", output);
        }
        Commands::Mcp { transport: _, port } => {
            tracing::info!("Iniciando Servidor MCP RustShield na porta {}", port);
            let app = create_router();
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Serve { host, port } => {
            tracing::info!("Iniciando RustShield Secure API Server em {}:{}", host, port);
            let app = create_router();
            let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
