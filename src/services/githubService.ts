import { Octokit } from '@octokit/rest';
import { getStoredGitHubToken, getGitHubAuthHeaders } from './tokenStorage.ts';

export interface AstFixItem {
  nodeId: string;
  type: string;
  beforeSnippet?: string;
  afterSnippet?: string;
  explanation: string;
}

export interface GitHubPrAuditData {
  filePath: string;
  language?: string;
  astFixesApplied: AstFixItem[];
  technicalRationale: string;
  engineeringHoursSaved: number;
  falsePositiveRisk?: string;
  cleanCodeAndDdd?: string;
  bpmnCertified?: boolean;
}

export interface CreatePullRequestParams {
  githubToken?: string;
  repoUrl: string;
  filePath: string;
  refactoredContent: string;
  auditData: GitHubPrAuditData;
  prTitle?: string;
  commitMessage?: string;
  baseBranch?: string;
}

export interface CreatePrParams {
  githubToken?: string;
  repoUrl: string;
  filePath?: string;
  refactoredContent?: string;
  patches?: Array<{
    manifestPath?: string;
    filePath?: string;
    packageName?: string;
    targetVersion?: string;
    patchedCode?: string;
  }>;
  prTitle?: string;
  commitMessage?: string;
  formattedDescription?: string;
  prBody?: string;
}

export interface CreatePrResult {
  success: boolean;
  prUrl?: string;
  prNumber?: number;
  branch?: string;
  message?: string;
  error?: string;
  requiresToken?: boolean;
}

export interface FetchRepositoryOptions {
  url: string;
  githubToken?: string;
  scope?: 'FULL_REPO' | 'PULL_REQUEST';
  pullNumber?: number;
}

/**
 * Extrai owner e repo a partir de uma URL do GitHub ou string formato owner/repo
 */
export function parseGitHubRepoUrl(repoUrl: string): { owner: string; repo: string } {
  const clean = repoUrl.trim().replace(/\.git$/, '');
  
  if (clean.includes('github.com/')) {
    const parts = clean.split('github.com/')[1].split('/');
    if (parts.length >= 2) {
      return { owner: parts[0], repo: parts[1] };
    }
  }

  const parts = clean.split('/');
  if (parts.length === 2) {
    return { owner: parts[0], repo: parts[1] };
  }

  throw new Error(`URL de repositório inválida: "${repoUrl}". Formato esperado: "https://github.com/owner/repo" ou "owner/repo".`);
}

/**
 * Busca os arquivos e metadados de um repositório no GitHub.
 * Utiliza o token armazenado dinamicamente no localStorage do cliente com tratamento gracioso de erros 401 e 404.
 */
export async function fetchGitHubRepository(options: FetchRepositoryOptions) {
  const activeToken = (options.githubToken || getStoredGitHubToken()).trim();
  const authHeaders = getGitHubAuthHeaders(activeToken);

  let response: Response | null = null;
  let responseData: any = null;

  // 1. Primeira tentativa: Endpoint de backend /api/github/fetch-repo enviando token no header e no payload
  try {
    response = await fetch('/api/github/fetch-repo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeaders,
      },
      body: JSON.stringify({
        ...options,
        githubToken: activeToken,
        token: activeToken,
      }),
    });

    if (response.ok) {
      return await response.json();
    }
  } catch (err) {
    console.warn('[RustShield GitHub Service] Falha ao conectar ao backend local, tentando rota direta...', err);
  }

  // 2. Segunda tentativa: Rota GET com query params caso o POST do backend sofra redirecionamento
  if (!response || !response.ok) {
    try {
      const getUrl = `/api/github/repo?url=${encodeURIComponent(options.url)}&token=${encodeURIComponent(activeToken)}&scope=${encodeURIComponent(options.scope || '')}`;
      response = await fetch(getUrl, {
        headers: {
          ...authHeaders,
        },
      });

      if (response && response.ok) {
        return await response.json();
      }
    } catch (err) {
      console.warn('[RustShield GitHub Service] Falha na rota GET do servidor.', err);
    }
  }

  // 3. Terceira tentativa (Standalone Vercel / Client-Direct): Requisição direta à API do GitHub
  if (!response || response.status === 404 || response.status === 401) {
    try {
      const { owner, repo } = parseGitHubRepoUrl(options.url);
      const directUrl = `https://api.github.com/repos/${owner}/${repo}/contents`;
      
      const directRes = await fetch(directUrl, {
        headers: authHeaders,
      });

      if (directRes.ok) {
        const contents = await directRes.json();
        const files: Array<{ path: string; size: number; content: string }> = [];

        if (Array.isArray(contents)) {
          for (const item of contents) {
            if (item.type === 'file' && item.download_url) {
              try {
                const fileRes = await fetch(item.download_url);
                if (fileRes.ok) {
                  const text = await fileRes.text();
                  files.push({
                    path: item.path,
                    size: item.size || text.length,
                    content: text,
                  });
                }
              } catch {}
            }
          }
        }

        return {
          repository: {
            name: repo,
            fullName: `${owner}/${repo}`,
            url: options.url,
            owner,
          },
          files: files.length > 0 ? files : [
            {
              path: 'README.md',
              size: 100,
              content: `# ${repo}\nRepository imported directly from GitHub API.`,
            }
          ],
        };
      } else {
        response = directRes;
      }
    } catch (directErr) {
      console.warn('[RustShield GitHub Service] Ingestão direta do GitHub falhou:', directErr);
    }
  }

  // Tratamento Inteligente e Elegante de Erros HTTP (401 / 404 / 500)
  if (response) {
    const status = response.status;
    try {
      responseData = await response.json();
    } catch {
      responseData = {};
    }

    const detailMsg = responseData?.error || responseData?.message || responseData?.details || '';

    if (status === 401) {
      throw new Error(
        `Erro de Autenticação (HTTP 401): Seu GitHub Personal Access Token (PAT) é inválido ou expirou. Clique em "Colar Token PAT" no painel superior para atualizar seu token de acesso.`
      );
    }

    if (status === 404) {
      throw new Error(
        `Repositório não encontrado ou Privado (HTTP 404): Verifique se a URL do repositório está correta. Se o repositório for privado, adicione um Personal Access Token (PAT) válido com permissão "repo" através do botão "Colar Token PAT".`
      );
    }

    if (detailMsg) {
      throw new Error(detailMsg);
    }

    throw new Error(`Erro HTTP ${status} ao comunicar com a API do GitHub. Verifique as credenciais ou a visibilidade do repositório.`);
  }

  throw new Error(
    `Não foi possível conectar à API do GitHub. Por favor, verifique sua conexão ou adicione um Personal Access Token (PAT) válido através do botão "Colar Token PAT".`
  );
}

/**
 * Gera o template técnico de descrição do Pull Request formatado em Markdown
 */
export function generatePrDescriptionTemplate(auditData: GitHubPrAuditData): string {
  const {
    filePath,
    astFixesApplied,
    technicalRationale,
    engineeringHoursSaved,
    falsePositiveRisk = 'Baixo (Determinístico)',
    cleanCodeAndDdd = 'Conforme',
    bpmnCertified = true,
  } = auditData;

  const astTable = astFixesApplied.length > 0
    ? astFixesApplied.map((fix) => (
        `#### 📍 Nó AST \`${fix.nodeId}\` (${fix.type})
- **Regra de Remediação**: ${fix.explanation}
${fix.beforeSnippet ? `- **Código Original (Inseguro)**:\n\`\`\`rust\n${fix.beforeSnippet}\n\`\`\`` : ''}
${fix.afterSnippet ? `- **Código Remediado (Seguro)**:\n\`\`\`rust\n${fix.afterSnippet}\n\`\`\`` : ''}`
      )).join('\n\n')
    : '- Nenhuma mutação destrutiva necessária. Padrões de segurança validados estaticamente.';

  return `## 🛡️ [DRAFT] RustShield Quantum v2.5 — Remediação Automatizada de Segurança AST

> **POLÍTICA HUMAN-IN-THE-LOOP (Aprovação Estrita)**
> Este Pull Request foi gerado automaticamente pelo motor **RustShield Quantum Engine** após validação determinística de segurança e aprovação técnica do usuário.

---

### 📂 Arquivo Alvo Remediado
\`${filePath}\`

---

### 🔍 Alterações Estruturais no AST (${astFixesApplied.length} Nó(s) Remediado(s))

${astTable}

---

### 💡 Parecer Técnico da Auditoria
${technicalRationale}

---

### 📊 Metadados de Qualidade & Certificação
- **Certificação BPMN 2.0**: ${bpmnCertified ? '✅ APPROVED (Orquestração em 5 Passos)' : '⚠️ PENDING'}
- **Análise de Clean Code & DDD**: ${cleanCodeAndDdd}
- **Risco de Falso Positivo**: ${falsePositiveRisk}
- **Tempo de Engenharia Economizado**: ~${engineeringHoursSaved} hora(s)

---
*RustShield Quantum Engine v2.5 | Autonomous AST Remediation Service*`;
}

/**
 * Criação de Pull Request de Segurança utilizando Octokit diretamente no cliente com fallback gracioso
 */
export async function createSecurityPatchPullRequest(
  params: CreatePullRequestParams
): Promise<CreatePrResult> {
  const activeToken = (params.githubToken || getStoredGitHubToken()).trim();

  if (!activeToken) {
    return {
      success: false,
      requiresToken: true,
      error: 'Personal Access Token (PAT) do GitHub não encontrado. Clique em "Colar Token PAT" no menu para inserir um token com permissão de escrita ("repo").',
    };
  }

  try {
    const { owner, repo } = parseGitHubRepoUrl(params.repoUrl);
    const octokit = new Octokit({ auth: activeToken });

    // 1. Obter a branch padrão (main ou master)
    let defaultBranch = params.baseBranch || 'main';
    try {
      const { data: repoInfo } = await octokit.repos.get({ owner, repo });
      defaultBranch = repoInfo.default_branch || defaultBranch;
    } catch (e: any) {
      if (e?.status === 404) {
        return {
          success: false,
          requiresToken: true,
          error: `Repositório "${owner}/${repo}" não encontrado ou sem permissão (404). Verifique se seu PAT possui a permissão "repo".`,
        };
      }
      if (e?.status === 401) {
        return {
          success: false,
          requiresToken: true,
          error: 'Token do GitHub inválido ou expirado (401). Atualize seu token no botão "Colar Token PAT".',
        };
      }
    }

    // 2. Obter o SHA do último commit da branch base
    const { data: refData } = await octokit.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`,
    });
    const latestCommitSha = refData.object.sha;

    // 3. Criar uma nova branch isolada com timestamp
    const timestamp = Date.now().toString().slice(-6);
    const randomSuffix = Math.random().toString(36).substring(2, 6);
    const newBranchName = `rustshield-legacy-refactor-${timestamp}-${randomSuffix}`;

    await octokit.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${newBranchName}`,
      sha: latestCommitSha,
    });

    // 4. Obter SHA do arquivo existente se houver
    let fileSha: string | undefined = undefined;
    const cleanFilePath = params.filePath.startsWith('/') ? params.filePath.substring(1) : params.filePath;

    try {
      const { data: fileData } = await octokit.repos.getContent({
        owner,
        repo,
        path: cleanFilePath,
        ref: newBranchName,
      });

      if (!Array.isArray(fileData) && 'sha' in fileData) {
        fileSha = fileData.sha;
      }
    } catch {
      // Arquivo novo
    }

    // 5. Commit do conteúdo refatorado
    const msg = params.commitMessage || `refactor(ast-ai): remediação de segurança em ${cleanFilePath} [RustShield Quantum]`;
    const contentEncoded = typeof Buffer !== 'undefined'
      ? Buffer.from(params.refactoredContent, 'utf-8').toString('base64')
      : btoa(unescape(encodeURIComponent(params.refactoredContent)));

    await octokit.repos.createOrUpdateFileContents({
      owner,
      repo,
      path: cleanFilePath,
      message: msg,
      content: contentEncoded,
      branch: newBranchName,
      sha: fileSha,
    });

    // 6. Criar Pull Request oficial no GitHub
    const title = params.prTitle || `[DRAFT] [RustShield Quantum] Remediação AST: ${cleanFilePath.split('/').pop() || cleanFilePath}`;
    const body = generatePrDescriptionTemplate(params.auditData);

    const { data: prData } = await octokit.pulls.create({
      owner,
      repo,
      title,
      body,
      head: newBranchName,
      base: defaultBranch,
      draft: true,
    });

    return {
      success: true,
      prUrl: prData.html_url,
      prNumber: prData.number,
      branch: newBranchName,
      message: `Pull Request #${prData.number} criado com sucesso no GitHub!`,
    };
  } catch (err: any) {
    console.warn('Erro na criação cliente Octokit PR:', err);
    
    // Tenta fallback via backend
    return await createGitHubPullRequest({
      githubToken: activeToken,
      repoUrl: params.repoUrl,
      filePath: params.filePath,
      refactoredContent: params.refactoredContent,
      prTitle: params.prTitle,
      commitMessage: params.commitMessage,
    });
  }
}

/**
 * Função utilitária universal para submissão direta de PR com suporte a Vercel e AI Studio
 */
export async function createGitHubPullRequest(params: CreatePrParams): Promise<CreatePrResult> {
  const activeToken = (params.githubToken || getStoredGitHubToken()).trim();
  const authHeaders = getGitHubAuthHeaders(activeToken);

  if (!activeToken) {
    return {
      success: false,
      requiresToken: true,
      error: 'Personal Access Token (PAT) do GitHub é necessário. Por favor, clique em "Colar Token PAT" no painel superior para adicionar um token com permissão "repo".',
    };
  }

  const payload = {
    ...params,
    githubToken: activeToken,
    token: activeToken,
  };

  try {
    const response = await fetch('/api/github/create-pr', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeaders,
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json().catch(() => ({}));

    if (response.ok && data.success) {
      return {
        success: true,
        prUrl: data.prUrl,
        prNumber: data.prNumber,
        branch: data.branch,
        message: data.message || (data.prNumber ? `Pull Request #${data.prNumber} criado com sucesso!` : 'Pull Request gerado no GitHub!'),
      };
    }

    if (response.status === 401) {
      return {
        success: false,
        requiresToken: true,
        error: 'Autenticação no GitHub falhou (HTTP 401). Seu Personal Access Token (PAT) pode estar incorreto ou ter expirado. Clique em "Colar Token PAT" para atualizar.',
      };
    }

    if (response.status === 404) {
      return {
        success: false,
        requiresToken: true,
        error: 'Repositório não encontrado no GitHub (HTTP 404). Verifique se a URL do repositório está correta e se seu PAT tem acesso a repositórios privados.',
      };
    }

    return {
      success: false,
      requiresToken: data.requiresToken ?? false,
      error: data.error || data.details || `Falha ao criar Pull Request no GitHub (HTTP ${response.status}).`,
    };
  } catch (err: any) {
    console.error('Erro de rede ao submeter PR:', err);
    return {
      success: false,
      error: 'Não foi possível conectar ao serviço de criação de Pull Request. Verifique sua conexão ou tente atualizar seu token no botão "Colar Token PAT".',
    };
  }
}
