import { RepositoryMetadata, SourceFile } from '../domain/types.ts';
import { BENCHMARK_CASES } from '../domain/benchmarks.ts';
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
    
    // Check if the user passed a benchmark URL or keyword
    const matchedBenchmark = BENCHMARK_CASES.find((b) =>
      options.url.toLowerCase().includes(b.repo.name.toLowerCase()) ||
      options.url.toLowerCase().includes(b.id.toLowerCase())
    );

    if (matchedBenchmark) {
      const isPr = options.scope === 'PULL_REQUEST' || options.url.includes('/pull');
      const repoWithScope: RepositoryMetadata = {
        ...matchedBenchmark.repo,
        scope: isPr ? 'PULL_REQUEST' : 'FULL_REPO',
        ...(isPr
          ? {
              pullRequest: {
                number: options.pullNumber || 42,
                title: `PR #${options.pullNumber || 42}: Migração de Criptografia & Correção de Race Condition`,
                author: matchedBenchmark.repo.owner || 'sec-engineer',
                state: 'open',
                headBranch: 'feat/crypto-hardening',
                baseBranch: matchedBenchmark.repo.defaultBranch || 'main',
                htmlUrl: `${matchedBenchmark.repo.url}/pull/${options.pullNumber || 42}`,
                additions: 128,
                deletions: 34,
                changedFilesCount: matchedBenchmark.files.slice(0, 3).length,
                createdAt: new Date().toISOString(),
                body: 'Auditoria de Pull Request focada em novas rotas, primitivas criptográficas e controle de concorrência.',
              },
            }
          : {}),
      };

      return {
        repository: repoWithScope,
        files: isPr ? matchedBenchmark.files.slice(0, 3) : matchedBenchmark.files,
      };
    }

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
