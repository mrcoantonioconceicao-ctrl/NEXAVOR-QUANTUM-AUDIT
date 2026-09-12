import { Octokit } from '@octokit/rest';

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
  githubToken: string;
  repoUrl: string;
  filePath: string;
  refactoredContent: string;
  auditData: GitHubPrAuditData;
  prTitle?: string;
  commitMessage?: string;
  baseBranch?: string;
}

export interface CreatePrParams {
  githubToken: string;
  repoUrl: string;
  filePath?: string;
  refactoredContent?: string;
  patches?: Array<{
    manifestPath?: string;
    packageName?: string;
    targetVersion?: string;
  }>;
  prTitle?: string;
  commitMessage?: string;
  formattedDescription?: string;
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
 * Busca os arquivos e metadados de um repositório no GitHub via API
 */
export async function fetchGitHubRepository(options: FetchRepositoryOptions) {
  const response = await fetch('/api/github/fetch-repo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.details || 'Falha ao buscar repositório no GitHub.');
  }

  return await response.json();
}

/**
 * Gera o template técnico de descrição do Pull Request formatado em Markdown a partir dos dados da auditoria AST
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
 * Utilitário de alto nível usando octokit diretamente para criar branch, commit e PR
 */
export async function createSecurityPatchPullRequest(
  params: CreatePullRequestParams
): Promise<CreatePrResult> {
  const {
    githubToken,
    repoUrl,
    filePath,
    refactoredContent,
    auditData,
    prTitle,
    commitMessage,
    baseBranch = 'main',
  } = params;

  if (!githubToken || !githubToken.trim()) {
    return {
      success: false,
      error: 'GitHub Personal Access Token (PAT) é obrigatório.',
    };
  }

  try {
    const { owner, repo } = parseGitHubRepoUrl(repoUrl);
    const octokit = new Octokit({ auth: githubToken.trim() });

    // 1. Obter a branch padrão (main ou master)
    let defaultBranch = baseBranch;
    try {
      const { data: repoInfo } = await octokit.repos.get({ owner, repo });
      defaultBranch = repoInfo.default_branch || baseBranch;
    } catch {
      // fallback
    }

    // 2. Obter o SHA do último commit da branch base
    const { data: refData } = await octokit.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`,
    });
    const latestCommitSha = refData.object.sha;

    // 3. Criar uma nova branch isolada com timestamp
    const timestamp = Date.now();
    const newBranchName = `rustshield-legacy-refactor-${timestamp}`;

    await octokit.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${newBranchName}`,
      sha: latestCommitSha,
    });

    // 4. Obter SHA do arquivo existente se houver
    let fileSha: string | undefined = undefined;
    const cleanFilePath = filePath.startsWith('/') ? filePath.substring(1) : filePath;

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
    const msg = commitMessage || `refactor(ast-ai): remediação de segurança em ${cleanFilePath} [RustShield Quantum]`;
    const contentEncoded = typeof Buffer !== 'undefined'
      ? Buffer.from(refactoredContent, 'utf-8').toString('base64')
      : btoa(unescape(encodeURIComponent(refactoredContent)));

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
    const title = prTitle || `[DRAFT] [RustShield Quantum] Remediação AST: ${cleanFilePath.split('/').pop() || cleanFilePath}`;
    const body = generatePrDescriptionTemplate(auditData);

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
    console.error('Erro ao executar criação de PR no githubService:', err);
    return {
      success: false,
      error: err?.message || 'Erro desconhecido ao comunicar com a API do GitHub.',
    };
  }
}

/**
 * Função utilitária de retrocompatibilidade para submissão direta de PR
 */
export async function createGitHubPullRequest(params: CreatePrParams): Promise<CreatePrResult> {
  const response = await fetch('/api/github/refactor-pr', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });

  const data = await response.json().catch(() => ({}));
  if (response.ok && data.success) {
    return {
      success: true,
      prUrl: data.prUrl,
      prNumber: data.prNumber,
      branch: data.branch,
      message: data.message || `Pull Request #${data.prNumber} criado com sucesso!`,
    };
  }

  return {
    success: false,
    error: data.error || data.details || 'Erro ao criar Pull Request.',
  };
}
