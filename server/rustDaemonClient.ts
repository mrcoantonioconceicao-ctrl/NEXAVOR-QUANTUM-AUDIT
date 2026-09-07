/**
 * Gateway REST/MCP Client em Node.js/TypeScript para comunicação IPC de alta performance
 * com o RustShield Core Daemon (Axum rodando em 127.0.0.1:4040).
 * 
 * Aplica timeout rígido de 3000ms via AbortSignal.
 */

export interface AstParseDaemonResponse {
  filename: string;
  functionsFound: Array<{
    name: string;
    isUnsafe: boolean;
    hasCheckedArithmetic: boolean;
  }>;
  memorySafetyScore: number;
  pqcCompliance: boolean;
}

export interface FuzzVerifyDaemonResponse {
  target: string;
  status: 'PASSED' | 'CRASH_DETECTED' | 'TIMEOUT';
  iterationsExecuted: number;
  coveragePercentage: number;
  sanitizerLog?: string;
}

export interface ConstantTimeCheckResponse {
  subroutineName: string;
  isConstantTime: boolean;
  timingVarianceNs: number;
  sideChannelVulnerabilityDetected: boolean;
}

export class RustDaemonClient {
  private static readonly DAEMON_BASE_URL = process.env.RUST_DAEMON_URL || 'http://127.0.0.1:4040';
  private static readonly TIMEOUT_MS = 3000;

  /**
   * Helper privado para efetuar chamadas HTTP POST tipadas com timeout de 3000ms
   */
  private static async request<T>(endpoint: string, payload: Record<string, any>): Promise<T> {
    const url = `${this.DAEMON_BASE_URL}${endpoint}`;
    
    // Timeout rígido de 3000ms
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'RustShield-Node-Gateway/2.2',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(`Daemon Axum retornou HTTP ${response.status}: ${errorText}`);
      }

      return (await response.json()) as T;
    } catch (error: any) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        console.warn(`[RustDaemonClient] Timeout estourado (>3000ms) ao requisitar ${endpoint}.`);
        throw new Error(`TIMEOUT_DAEMON_EXCEEDED: O daemon Rust em 127.0.0.1:4040 não respondeu em ${this.TIMEOUT_MS}ms.`);
      }
      throw error;
    }
  }

  /**
   * Requisita o parsing de AST de alta performance ao Daemon Rust
   */
  public static async parseAst(code: string, filename: string): Promise<AstParseDaemonResponse> {
    return this.request<AstParseDaemonResponse>('/api/ast/parse', { code, filename });
  }

  /**
   * Requisita verificação de Fuzzing em tempo real ao Daemon Rust
   */
  public static async verifyFuzzTarget(target: string, inputHex: string): Promise<FuzzVerifyDaemonResponse> {
    return this.request<FuzzVerifyDaemonResponse>('/api/fuzz/verify', { target, inputHex });
  }

  /**
   * Requisita análise de canal lateral / Constant-Time ao Daemon Rust
   */
  public static async checkConstantTime(subroutineName: string, executionTrace: number[]): Promise<ConstantTimeCheckResponse> {
    return this.request<ConstantTimeCheckResponse>('/api/crypto/constant-time', { subroutineName, executionTrace });
  }
}
