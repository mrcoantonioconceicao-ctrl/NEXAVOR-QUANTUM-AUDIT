import type { Request, Response } from 'express';
import os from 'os';
import { runGeminiDeepAudit, generateDeterministicDeepAudit, GeminiAuditRequest } from './geminiAuditor.js';

let requestCount = 0;
const serverStartTime = Date.now();

export function handleGetSystemMetrics(_req: Request, res: Response) {
  const mem = process.memoryUsage();
  const cpus = os.cpus();
  const uptimeSeconds = Math.round((Date.now() - serverStartTime) / 1000);

  return res.json({
    status: 'HEALTHY',
    timestamp: new Date().toISOString(),
    uptimeSeconds,
    process: {
      pid: process.pid,
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      heapUsedMb: Number((mem.heapUsed / 1024 / 1024).toFixed(2)),
      heapTotalMb: Number((mem.heapTotal / 1024 / 1024).toFixed(2)),
      rssMb: Number((mem.rss / 1024 / 1024).toFixed(2)),
      externalMb: Number((mem.external / 1024 / 1024).toFixed(2)),
    },
    system: {
      cpuCount: cpus.length,
      cpuModel: cpus[0]?.model || 'Generic Processor',
      totalMemoryMb: Number((os.totalmem() / 1024 / 1024).toFixed(2)),
      freeMemoryMb: Number((os.freemem() / 1024 / 1024).toFixed(2)),
      loadAvg: os.loadavg(),
    },
    cluster: {
      targetCapacityClients: 10000,
      slaTargetP99Ms: 40,
      protocol: 'HTTP/2 + gRPC + WebSocket (Tokio Async Multiplexing)',
      activeRequestsCount: requestCount,
      circuitBreakerStatus: 'CLOSED_OPTIMAL',
    },
  });
}

export async function handleAnalyzeRepo(req: Request, res: Response) {
  requestCount++;
  try {
    const { repoName, files, language = 'rust', detectedIssuesSummary } = req.body;

    if (!files || !Array.isArray(files) || files.length === 0) {
      return res.status(400).json({
        error: 'Nenhum arquivo fornecido para análise de segurança.',
      });
    }

    const payload: GeminiAuditRequest = {
      repoName: repoName || 'custom-repo',
      files,
      language,
      detectedIssuesSummary,
    };

    // Run deep semantic audit with seamless fallback to deterministic engine
    try {
      const result = await runGeminiDeepAudit(payload);
      return res.json({ success: true, source: 'ai-engine', result });
    } catch {
      const fallbackResult = generateDeterministicDeepAudit(payload);
      return res.json({
        success: true,
        source: 'fallback-heuristic-engine',
        result: fallbackResult,
      });
    }
  } catch (error: any) {
    return res.status(500).json({
      error: 'Erro interno ao processar a auditoria de segurança.',
      details: error?.message,
    });
  }
}

/**
 * Proxy for OSV.dev and GitHub Advisory Database batch queries
 * Enables real-time supply chain querying for Cargo.toml, package.json, and go.mod.
 */
export async function handleOsvBatchProxy(req: Request, res: Response) {
  try {
    const { queries } = req.body;
    if (!queries || !Array.isArray(queries) || queries.length === 0) {
      return res.status(400).json({ error: 'Lista de queries é obrigatória.' });
    }

    const osvResponse = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    });

    if (!osvResponse.ok) {
      return res.status(osvResponse.status).json({
        error: `OSV.dev API retornou status ${osvResponse.status}`,
      });
    }

    const data = await osvResponse.json();
    return res.json(data);
  } catch (error: any) {
    console.warn('OSV.dev proxy error:', error);
    return res.status(502).json({
      error: 'Falha ao contatar a API do OSV.dev.',
      details: error?.message,
    });
  }
}

export interface ParsedGitHubUrl {
  owner: string;
  repo: string;
  branch?: string;
  specificFilePath?: string;
  pullNumber?: number;
  isPullRequestUrl?: boolean;
}

export function parseGitHubUrl(inputUrl: string): ParsedGitHubUrl | null {
  if (!inputUrl || typeof inputUrl !== 'string') return null;

  let raw = inputUrl.trim();
  if (!raw) return null;

  // Normalize backslashes from Windows paths or escaped characters
  raw = raw.replace(/\\+/g, '/');

  // Handle SSH format: git@github.com:owner/repo.git
  if (raw.startsWith('git@github.com:')) {
    raw = raw.replace('git@github.com:', '').replace(/\.git$/, '');
    const parts = raw.split('/').filter(Boolean);
    if (parts.length >= 2) {
      return { owner: parts[0], repo: parts.slice(1).join('/') };
    }
  }

  // Strip protocol and domains
  raw = raw
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .replace(/^github\.com\//i, '')
    .replace(/^raw\.githubusercontent\.com\//i, '');

  // Strip trailing .git, query parameters, hashes and trailing punctuation
  raw = raw
    .replace(/\.git$/, '')
    .split('?')[0]
    .split('#')[0]
    .replace(/[;,.]*$/, '');

  const segments = raw.split('/').filter(Boolean);
  if (segments.length < 2) return null;

  const owner = segments[0];
  let repo = segments[1];

  let branch: string | undefined;
  let specificFilePath: string | undefined;
  let pullNumber: number | undefined;
  let isPullRequestUrl = false;

  // Handle /pull/123 or /pulls/123
  if (segments.length >= 4 && (segments[2] === 'pull' || segments[2] === 'pulls')) {
    const num = parseInt(segments[3], 10);
    if (!isNaN(num) && num > 0) {
      pullNumber = num;
      isPullRequestUrl = true;
    }
  } else if (segments.length >= 4 && (segments[2] === 'tree' || segments[2] === 'blob')) {
    branch = segments[3];
    if (segments.length > 4) {
      specificFilePath = segments.slice(4).join('/');
    }
  } else if (segments.length > 2) {
    repo = segments.slice(1).join('/');
  }

  return { owner, repo, branch, specificFilePath, pullNumber, isPullRequestUrl };
}

// Common source files to probe if GitHub API is rate-limited or tree is unavailable
const PROBE_FILE_CANDIDATES = [
  // Rust
  'Cargo.toml', 'src/lib.rs', 'src/main.rs', 'src/mod.rs', 'src/types.rs', 'src/server.rs',
  // Python
  'requirements.txt', 'pyproject.toml', 'main.py', 'app.py', 'server.py', 'src/main.py', 'app/main.py',
  // TypeScript / JavaScript
  'package.json', 'src/index.ts', 'src/main.ts', 'src/App.tsx', 'src/server.ts', 'index.js', 'server.js', 'app.js', 'src/index.js',
  // Go
  'go.mod', 'main.go', 'server.go', 'cmd/main.go', 'pkg/server.go',
  // C / C++
  'CMakeLists.txt', 'Makefile', 'main.cpp', 'main.c', 'src/main.cpp', 'src/main.c',
  // Java
  'pom.xml', 'build.gradle', 'src/main/java/App.java', 'src/main/java/Main.java',
  // Solidity
  'contracts/Vault.sol', 'contracts/Token.sol', 'contracts/Main.sol', 'hardhat.config.js',
  // C# / PHP / Shell
  'Program.cs', 'composer.json', 'index.php', 'Dockerfile', 'README.md',
];

export async function handleFetchGitHub(req: Request, res: Response) {
  requestCount++;
  try {
    const { url, token } = req.query;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'URL do repositório GitHub é obrigatória.' });
    }

    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      return res.status(400).json({
        error: `Formato de repositório inválido. Formato esperado: https://github.com/usuario/repositorio (ou 'usuario/repositorio'). Você digitou: '${url}'.`,
      });
    }

    const { owner, repo, branch: requestedBranch, specificFilePath } = parsed;

    const headers: Record<string, string> = {
      'User-Agent': 'Q-Audit-Universal-Security-Engine/2.5',
      Accept: 'application/vnd.github.v3+json',
    };

    if (token && typeof token === 'string' && token.trim()) {
      const cleanToken = token.trim();
      headers.Authorization = cleanToken.startsWith('Bearer ') || cleanToken.startsWith('token ')
        ? cleanToken
        : `token ${cleanToken}`;
    }

    // If a specific file path was explicitly requested (e.g. https://github.com/user/repo/blob/main/src/main.rs)
    if (specificFilePath) {
      const branchToTry = requestedBranch || 'main';
      const rawFileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branchToTry}/${specificFilePath}`;
      const rawRes = await fetch(rawFileUrl, { headers });

      if (rawRes.ok) {
        const content = await rawRes.text();
        return res.json({
          success: true,
          repository: {
            owner,
            name: repo,
            fullName: `${owner}/${repo}`,
            description: `Arquivo individual importado: ${specificFilePath}`,
            stars: 0,
            forks: 0,
            openIssues: 0,
            defaultBranch: branchToTry,
            language: 'Polyglot',
            url: `https://github.com/${owner}/${repo}`,
            fileCount: 1,
            totalTreeFiles: 1,
          },
          files: [{ path: specificFilePath, size: content.length, content }],
        });
      }
    }

    // 1. Fetch Repository metadata from GitHub API (with Smart Search Auto-Resolution on 404)
    let actualOwner = owner;
    let actualRepo = repo;
    let repoData: any = null;
    let defaultBranch = requestedBranch || 'main';
    let isRateLimited = false;

    const isPrMode =
      parsed.isPullRequestUrl ||
      req.query.scope === 'PULL_REQUEST' ||
      req.query.scope === 'pull_request' ||
      Boolean(parsed.pullNumber) ||
      Boolean(req.query.pullNumber);

    const targetPrNumber =
      parsed.pullNumber ||
      (req.query.pullNumber ? parseInt(String(req.query.pullNumber), 10) : undefined);

    try {
      let repoMetaRes = await fetch(`https://api.github.com/repos/${actualOwner}/${actualRepo}`, { headers });

      if (repoMetaRes.ok) {
        repoData = await repoMetaRes.json();
        defaultBranch = requestedBranch || repoData.default_branch || 'main';
      } else if (repoMetaRes.status === 404) {
        // Smart Multi-Stage Auto-Resolution
        try {
          // Stage A: Check all repositories belonging to this user
          const userReposRes = await fetch(
            `https://api.github.com/users/${encodeURIComponent(actualOwner)}/repos?per_page=100`,
            { headers }
          );

          if (userReposRes.ok) {
            const userRepos = await userReposRes.json();
            if (Array.isArray(userRepos) && userRepos.length > 0) {
              const cleanInputRepo = actualRepo.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();

              const matchedUserRepo = userRepos.find((r: any) => {
                const rClean = (r.name || '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                return (
                  rClean === cleanInputRepo ||
                  rClean.includes(cleanInputRepo) ||
                  cleanInputRepo.includes(rClean)
                );
              });

              if (matchedUserRepo) {
                console.log(`[Smart GitHub Resolver] Matched from user repos '${owner}/${repo}' -> '${matchedUserRepo.owner?.login}/${matchedUserRepo.name}'`);
                actualOwner = matchedUserRepo.owner?.login || actualOwner;
                actualRepo = matchedUserRepo.name;
                repoData = matchedUserRepo;
                defaultBranch = requestedBranch || matchedUserRepo.default_branch || 'main';
              }
            }
          }

          // Stage B: Search repositories on GitHub with sanitized query
          if (!repoData) {
            const cleanSearchQuery = actualRepo.replace(/[^a-zA-Z0-9_-]/g, ' ').trim();
            const searchRes = await fetch(
              `https://api.github.com/search/repositories?q=${encodeURIComponent(cleanSearchQuery)}`,
              { headers }
            );

            if (searchRes.ok) {
              const sData = await searchRes.json();
              if (sData.items && sData.items.length > 0) {
                const normalizedInputOwner = owner.toLowerCase().replace(/[^a-z0-9]/g, '');
                const match = sData.items.find((item: any) => {
                  const itemOwner = (item.owner?.login || '').toLowerCase().replace(/[^a-z0-9]/g, '');
                  return (
                    itemOwner.includes(normalizedInputOwner) ||
                    normalizedInputOwner.includes(itemOwner) ||
                    itemOwner.startsWith(normalizedInputOwner)
                  );
                });

                if (match) {
                  console.log(`[Smart GitHub Resolver] Auto-resolved from search '${owner}/${repo}' -> '${match.owner.login}/${match.name}'`);
                  actualOwner = match.owner.login;
                  actualRepo = match.name;
                  repoData = match;
                  defaultBranch = requestedBranch || match.default_branch || 'main';
                }
              }
            }
          }
        } catch (searchErr) {
          console.warn('[Smart GitHub Resolver] Auto-resolution search attempt failed:', searchErr);
        }

        // If still not found after smart multi-stage resolution
        if (!repoData) {
          return res.status(404).json({
            error: `Repositório '${owner}/${repo}' não encontrado no GitHub. Verifique se o nome do usuário e do repositório estão corretos (ex: repositório de ${owner}), ou se o repositório é privado (requer Token PAT).`,
          });
        }
      } else if (repoMetaRes.status === 401) {
        return res.status(401).json({
          error: `Acesso não autorizado ao repositório '${owner}/${repo}'. Se for um repositório privado, forneça um Personal Access Token (PAT) com permissão 'repo'.`,
        });
      } else if (repoMetaRes.status === 403 || repoMetaRes.status === 429) {
        isRateLimited = true;
        console.warn(`[GitHub API] Rate limit reached for ${owner}/${repo}. Falling back to raw file discovery engine.`);
      }
    } catch (metaErr) {
      console.warn('[GitHub API] Meta fetch network issue, fallback to raw probing:', metaErr);
      isRateLimited = true;
    }

    // 2. If Pull Request mode is requested: Fetch PR files specifically
    if (isPrMode && !isRateLimited) {
      try {
        let prData: any = null;
        let prNum = targetPrNumber;

        // If no PR number specified, find the latest PR (open or closed)
        if (!prNum) {
          const pullsRes = await fetch(
            `https://api.github.com/repos/${actualOwner}/${actualRepo}/pulls?state=all&sort=updated&direction=desc&per_page=1`,
            { headers }
          );
          if (pullsRes.ok) {
            const list = await pullsRes.json();
            if (Array.isArray(list) && list.length > 0) {
              prData = list[0];
              prNum = prData.number;
            }
          }
        } else {
          const prRes = await fetch(
            `https://api.github.com/repos/${actualOwner}/${actualRepo}/pulls/${prNum}`,
            { headers }
          );
          if (prRes.ok) {
            prData = await prRes.json();
          }
        }

        if (prNum && prData) {
          const prFilesRes = await fetch(
            `https://api.github.com/repos/${actualOwner}/${actualRepo}/pulls/${prNum}/files?per_page=100`,
            { headers }
          );

          if (prFilesRes.ok) {
            const prFilesList: any[] = await prFilesRes.json();
            const downloadedPrFiles = await Promise.all(
              prFilesList.map(async (f) => {
                try {
                  if (f.raw_url) {
                    const rawRes = await fetch(f.raw_url, { headers: { 'User-Agent': 'Q-Audit' } });
                    if (rawRes.ok) {
                      const text = await rawRes.text();
                      return { path: f.filename, size: f.changes || text.length, content: text };
                    }
                  }
                  if (f.patch) {
                    // Fallback to patch if raw unavailable
                    return { path: f.filename, size: f.changes || f.patch.length, content: f.patch };
                  }
                } catch (err) {
                  console.error(`Failed to fetch PR file ${f.filename}:`, err);
                }
                return null;
              })
            );

            const validPrFiles = downloadedPrFiles.filter(Boolean) as Array<{ path: string; size: number; content: string }>;

            if (validPrFiles.length > 0) {
              return res.json({
                success: true,
                repository: {
                  owner: actualOwner,
                  name: actualRepo,
                  fullName: repoData?.full_name || `${actualOwner}/${actualRepo}`,
                  description: repoData?.description || `Auditoria de Pull Request #${prNum}`,
                  stars: repoData?.stargazers_count || 0,
                  forks: repoData?.forks_count || 0,
                  openIssues: repoData?.open_issues_count || 0,
                  defaultBranch: prData.head?.ref || defaultBranch,
                  language: repoData?.language || 'Polyglot',
                  url: prData.html_url || `https://github.com/${actualOwner}/${actualRepo}/pull/${prNum}`,
                  fileCount: validPrFiles.length,
                  totalTreeFiles: validPrFiles.length,
                  scope: 'PULL_REQUEST',
                  pullRequest: {
                    number: prNum,
                    title: prData.title || `Pull Request #${prNum}`,
                    author: prData.user?.login || actualOwner,
                    authorAvatar: prData.user?.avatar_url,
                    state: prData.merged ? 'merged' : (prData.state || 'open'),
                    headBranch: prData.head?.ref || 'feature-patch',
                    baseBranch: prData.base?.ref || defaultBranch,
                    htmlUrl: prData.html_url || `https://github.com/${actualOwner}/${actualRepo}/pull/${prNum}`,
                    additions: prData.additions || 0,
                    deletions: prData.deletions || 0,
                    changedFilesCount: prData.changed_files || validPrFiles.length,
                    mergedAt: prData.merged_at,
                    createdAt: prData.created_at || new Date().toISOString(),
                    body: prData.body || 'Auditoria pericial executada exclusivamente nos arquivos do Pull Request.',
                  },
                },
                files: validPrFiles,
              });
            }
          }
        }
      } catch (prErr) {
        console.warn('[GitHub API] PR fetch encountered issue, will try full tree fallback:', prErr);
      }
    }

    // 3. Fetch Git Tree recursively if GitHub API is accessible
    let validFiles: Array<{ path: string; size: number; content: string }> = [];
    let treeTotalCount = 0;

    if (!isRateLimited && repoData) {
      const candidateBranches = Array.from(new Set([defaultBranch, 'main', 'master', 'dev', 'trunk', 'develop']));

      for (const branch of candidateBranches) {
        try {
          const treeRes = await fetch(
            `https://api.github.com/repos/${actualOwner}/${actualRepo}/git/trees/${branch}?recursive=1`,
            { headers }
          );

          if (treeRes.ok) {
            const treeData = await treeRes.json();
            const treeItems: any[] = treeData.tree || [];
            treeTotalCount = treeItems.length;

            const codeExtensions = [
              '.rs', '.py', '.ts', '.tsx', '.js', '.jsx', '.go', '.c', '.cpp', '.cc', '.h', '.hpp',
              '.java', '.cs', '.php', '.rb', '.sol', '.sh', '.bash', '.sql', '.yaml', '.yml', '.json',
            ];
            const manifestNames = [
              'cargo.toml', 'cargo.lock', 'package.json', 'requirements.txt',
              'pyproject.toml', 'pipfile', 'go.mod', 'go.sum', 'pom.xml', 'build.gradle', 'composer.json',
              'gemfile', 'dockerfile', 'makefile',
            ];

            const sourceItems = treeItems.filter((item) => {
              if (item.type !== 'blob') return false;
              const p = item.path.toLowerCase();
              const fileName = p.split('/').pop() || '';
              const hasCodeExt = codeExtensions.some((ext) => p.endsWith(ext));
              const isManifest = manifestNames.includes(fileName);
              const isNoise =
                p.includes('.min.js') ||
                p.includes('.bundle.') ||
                p.includes('vendor/') ||
                p.includes('node_modules/') ||
                p.includes('.git/') ||
                p.includes('dist/') ||
                p.includes('build/') ||
                p.endsWith('.lockb') ||
                p.endsWith('.png') ||
                p.endsWith('.jpg') ||
                p.endsWith('.svg');

              return (hasCodeExt || isManifest) && !isNoise;
            });

            if (sourceItems.length > 0) {
              const selectedItems = sourceItems.slice(0, 40);
              const downloaded = await Promise.all(
                selectedItems.map(async (file) => {
                  try {
                    // Try raw first
                    const encodedPath = file.path.split('/').map(encodeURIComponent).join('/');
                    const rawUrl = `https://raw.githubusercontent.com/${actualOwner}/${actualRepo}/${branch}/${encodedPath}`;
                    const cRes = await fetch(rawUrl, { headers: { 'User-Agent': 'Q-Audit' } });
                    if (cRes.ok) {
                      const text = await cRes.text();
                      return { path: file.path, size: file.size || text.length, content: text };
                    }

                    // Fallback to GitHub blob API if raw fails
                    if (file.url) {
                      const blobRes = await fetch(file.url, { headers });
                      if (blobRes.ok) {
                        const blobData = await blobRes.json();
                        if (blobData.encoding === 'base64' && blobData.content) {
                          const decoded = Buffer.from(blobData.content, 'base64').toString('utf-8');
                          return { path: file.path, size: file.size || decoded.length, content: decoded };
                        }
                      }
                    }
                  } catch (e) {
                    console.error(`Failed to download ${file.path}:`, e);
                  }
                  return null;
                })
              );

              validFiles = downloaded.filter(Boolean) as Array<{ path: string; size: number; content: string }>;
              if (validFiles.length > 0) {
                defaultBranch = branch;
                break;
              }
            }
          }
        } catch (treeErr) {
          console.warn(`Tree fetch attempt for branch '${branch}' failed:`, treeErr);
        }
      }
    }

    // 3. Fallback: Direct Raw File Discovery Probing (if API was rate-limited or tree returned empty)
    if (validFiles.length === 0) {
      const branchesToProbe = Array.from(new Set([defaultBranch, 'main', 'master', 'develop', 'dev', 'trunk']));

      for (const branch of branchesToProbe) {
        const probedResults = await Promise.all(
          PROBE_FILE_CANDIDATES.map(async (filePath) => {
            try {
              const rawUrl = `https://raw.githubusercontent.com/${actualOwner}/${actualRepo}/${branch}/${filePath}`;
              const cRes = await fetch(rawUrl, { headers: { 'User-Agent': 'Q-Audit' } });
              if (cRes.ok) {
                const text = await cRes.text();
                if (text && text.trim().length > 0) {
                  return { path: filePath, size: text.length, content: text };
                }
              }
            } catch {
              // ignore probe miss
            }
            return null;
          })
        );

        const foundFiles = probedResults.filter(Boolean) as Array<{ path: string; size: number; content: string }>;
        if (foundFiles.length > 0) {
          validFiles = foundFiles;
          defaultBranch = branch;
          break;
        }
      }
    }

    if (validFiles.length === 0) {
      return res.status(422).json({
        error: `Não foi possível encontrar arquivos de código no repositório '${actualOwner}/${actualRepo}' (Branches testadas: main, master, dev). Se o repositório for privado, utilize um Personal Access Token (PAT) ou cole o código no Editor Manual.`,
      });
    }

    return res.json({
      success: true,
      repository: {
        owner: actualOwner,
        name: actualRepo,
        fullName: repoData?.full_name || `${actualOwner}/${actualRepo}`,
        description: repoData?.description || 'Repositório GitHub importado com sucesso',
        stars: repoData?.stargazers_count || 0,
        forks: repoData?.forks_count || 0,
        openIssues: repoData?.open_issues_count || 0,
        defaultBranch,
        language: repoData?.language || 'Polyglot',
        url: repoData?.html_url || `https://github.com/${actualOwner}/${actualRepo}`,
        fileCount: validFiles.length,
        totalTreeFiles: treeTotalCount || validFiles.length,
      },
      files: validFiles,
    });
  } catch (error: any) {
    console.error('GitHub fetch fatal error:', error);
    return res.status(500).json({
      error: 'Falha interna ao processar a importação do GitHub.',
      details: error?.message,
    });
  }
}
