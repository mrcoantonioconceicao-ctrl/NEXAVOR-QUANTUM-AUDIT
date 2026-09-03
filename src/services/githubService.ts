import { RepositoryMetadata, SourceFile } from '../domain/types.ts';
import { detectFileLanguage } from '../domain/polyglotStaticEngine.ts';

export interface FetchRepoOptions {
  url: string;
  githubToken?: string;
  scope?: 'FULL_REPO' | 'PULL_REQUEST';
  pullNumber?: number;
}

export async function fetchGitHubRepository(
  urlOrOptions: string | FetchRepoOptions,
  legacyToken?: string
): Promise<{
  repository: RepositoryMetadata;
  files: SourceFile[];
}> {
  const options: FetchRepoOptions =
    typeof urlOrOptions === 'string'
      ? { url: urlOrOptions, githubToken: legacyToken }
      : urlOrOptions;

  const tokenParam = options.githubToken ? `&token=${encodeURIComponent(options.githubToken)}` : '';
  const scopeParam = options.scope ? `&scope=${encodeURIComponent(options.scope)}` : '';
  const prParam = options.pullNumber ? `&pullNumber=${encodeURIComponent(options.pullNumber)}` : '';
  
  const res = await fetch(`/api/github/repo?url=${encodeURIComponent(options.url)}${tokenParam}${scopeParam}${prParam}`);

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const message = errData.error || `Erro de conexão com o GitHub (${res.status} ${res.statusText})`;
    throw new Error(message);
  }

  const data = await res.json();

  if (!data.files || data.files.length === 0) {
    throw new Error('O repositório não retornou arquivos de código válidos.');
  }

  // Enrich files with language tags
  const enrichedFiles = data.files.map((f: SourceFile) => ({
    ...f,
    language: f.language || detectFileLanguage(f.path),
  }));

  return {
    repository: data.repository,
    files: enrichedFiles,
  };
}

export interface CreatePrParams {
  repoUrl: string;
  githubToken?: string;
  patches: Array<{
    manifestPath: string;
    packageName: string;
    currentVersion?: string;
    targetVersion: string;
    remediationCommand?: string;
  }>;
  prTitle?: string;
  prBody?: string;
}

export interface CreatePrResult {
  success: boolean;
  isSimulated?: boolean;
  requiresToken?: boolean;
  prUrl?: string;
  prNumber?: number;
  branch?: string;
  patchedFiles?: string[];
  message?: string;
  error?: string;
}

export async function createGitHubPullRequest(params: CreatePrParams): Promise<CreatePrResult> {
  try {
    const res = await fetch('/api/github/create-pr', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });

    const data = await res.json();
    if (!res.ok) {
      return {
        success: false,
        error: data.error || `Erro de conexão (${res.status})`,
      };
    }

    return data;
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Falha ao comunicar com o servidor.',
    };
  }
}

export async function submitPullRequestToRepo(
  owner: string,
  repo: string,
  patches: CreatePrParams['patches'],
  token?: string,
  prTitle?: string,
  prBody?: string
): Promise<CreatePrResult> {
  const repoUrl = `https://github.com/${owner}/${repo}`;
  try {
    const res = await fetch('/api/github/pulls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repoUrl,
        githubToken: token,
        patches,
        prTitle,
        prBody,
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      return {
        success: false,
        error: data.error || `Erro de comunicação com a API do GitHub (${res.status})`,
      };
    }

    return data;
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Falha na conexão ao enviar Pull Request.',
    };
  }
}


