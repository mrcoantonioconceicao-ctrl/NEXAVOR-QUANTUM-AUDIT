const PRIMARY_TOKEN_KEY = 'github_token';
const LEGACY_TOKEN_KEY = 'rustshield_github_pat';

/**
 * Recupera o token PAT do GitHub armazenado no localStorage do cliente.
 * Checa primeiro 'github_token' e em seguida 'rustshield_github_pat' como fallback.
 */
export function getStoredGitHubToken(): string {
  try {
    const primary = localStorage.getItem(PRIMARY_TOKEN_KEY);
    if (primary && primary.trim()) return primary.trim();

    const legacy = localStorage.getItem(LEGACY_TOKEN_KEY);
    if (legacy && legacy.trim()) return legacy.trim();

    return '';
  } catch {
    return '';
  }
}

/** Alias utilitário conveniente */
export const getGitHubToken = getStoredGitHubToken;

/**
 * Salva o token PAT do GitHub no localStorage do navegador.
 * Atualiza ambas as chaves ('github_token' e 'rustshield_github_pat') para máxima compatibilidade.
 */
export function setStoredGitHubToken(token: string): void {
  try {
    const clean = (token || '').trim();
    if (clean) {
      localStorage.setItem(PRIMARY_TOKEN_KEY, clean);
      localStorage.setItem(LEGACY_TOKEN_KEY, clean);
    } else {
      localStorage.removeItem(PRIMARY_TOKEN_KEY);
      localStorage.removeItem(LEGACY_TOKEN_KEY);
    }
  } catch (e) {
    console.warn('[RustShield TokenStorage] Falha ao salvar token no localStorage:', e);
  }
}

/** Alias utilitários convenientes */
export const saveGitHubToken = setStoredGitHubToken;

/**
 * Remove o token PAT do GitHub do localStorage.
 */
export function removeStoredGitHubToken(): void {
  try {
    localStorage.removeItem(PRIMARY_TOKEN_KEY);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
  } catch (e) {
    console.warn('[RustShield TokenStorage] Falha ao remover token do localStorage:', e);
  }
}

/** Alias utilitário conveniente */
export const removeGitHubToken = removeStoredGitHubToken;

/**
 * Gera os cabeçalhos de autorização dinâmicos para a API do GitHub.
 * Garante que a requisição nunca dependa de variáveis de ambiente estáticas do servidor.
 */
export function getGitHubAuthHeaders(customToken?: string): Record<string, string> {
  const token = (customToken || getStoredGitHubToken()).trim();
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
  };

  if (token) {
    headers['Authorization'] = token.startsWith('Bearer ') || token.startsWith('token ')
      ? token
      : `Bearer ${token}`;
  }

  return headers;
}
