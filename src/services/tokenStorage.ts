const TOKEN_KEY = 'rustshield_github_pat';

export function getStoredGitHubToken(): string {
  try {
    return (localStorage.getItem(TOKEN_KEY) || '').trim();
  } catch {
    return '';
  }
}

export function setStoredGitHubToken(token: string): void {
  try {
    const clean = token.trim();
    if (clean) {
      localStorage.setItem(TOKEN_KEY, clean);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  } catch (e) {
    console.warn('Falha ao salvar token no localStorage:', e);
  }
}
