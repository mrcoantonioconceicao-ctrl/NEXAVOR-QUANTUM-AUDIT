use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "rustshield")]
#[command(author = "RustShield Secure Core Team")]
#[command(version = "2.0.0")]
#[command(about = "High-Performance Memory-Safe AppSec, GRC & Static Analysis Engine")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Executa varredura estática de segurança e análise de dependências em um diretório ou arquivo
    Scan {
        /// Caminho do arquivo ou repositório a ser auditado
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Formato de saída (json, sarif, console)
        #[arg(short, long, default_value = "console")]
        format: String,

        /// Limite de falha de score de segurança (0-100)
        #[arg(long, default_value_t = 70)]
        fail_under: u32,
    },

    /// Executa refatoração determinística de segurança (In-Place ou Migração Polyglot)
    Refactor {
        /// Caminho do arquivo de código legado a refatorar
        #[arg(short, long)]
        file: String,

        /// Modo de destino (in-place, rust, go)
        #[arg(short, long, default_value = "in-place")]
        mode: CliRefactorMode,

        /// Gravar arquivo de saída diretamente
        #[arg(short, long, default_value_t = false)]
        write: bool,
    },

    /// Gera o Software Bill of Materials (SBOM) no padrão OWASP CycloneDX v1.5 JSON
    Sbom {
        /// Diretório do projeto
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Caminho do arquivo de saída
        #[arg(short, long, default_value = "bom.json")]
        output: String,
    },

    /// Inicia o Servidor MCP (Model Context Protocol) via Stdio ou HTTP para IDEs (Cursor/VSCode)
    Mcp {
        /// Modo de transporte (stdio ou http)
        #[arg(short, long, default_value = "stdio")]
        transport: String,

        /// Porta para transporte HTTP
        #[arg(short, long, default_value_t = 3001)]
        port: u16,
    },

    /// Inicia o Servidor Web API REST e MCP HTTP
    Serve {
        /// Host de escuta
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Porta de escuta
        #[arg(short, long, default_value_t = 3000)]
        port: u16,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliRefactorMode {
    InPlace,
    Rust,
    Go,
}
