import { Octokit } from "@octokit/rest";

export interface FileToCommit {
  path: string;
  content: string;
}

export interface PushMultipleFilesOptions {
  token?: string;
  commitMessage?: string;
  force?: boolean;
}

/**
 * Cria ou obtém instância da Octokit autenticada com token fornecido ou de variáveis de ambiente.
 */
export function getOctokitClient(token?: string): Octokit {
  const authToken =
    token ||
    process.env.GITHUB_TOKEN ||
    process.env.GITHUB_PAT ||
    process.env.GH_TOKEN;

  return new Octokit({
    auth: authToken,
  });
}

/**
 * Envia múltiplos arquivos para uma branch no GitHub em um ÚNICO commit atômico
 * utilizando a Git Data API (Blobs -> Tree -> Commit -> UpdateRef).
 * 
 * Isso soluciona a falha de sincronização onde apenas 1 arquivo era enviado,
 * garantindo que todos os diffs (ex: 12 arquivos refatorados) sejam incluídos no PR.
 *
 * @param owner Dono ou organização do repositório (ex: 'mrcoantonioconceicao-ctrl')
 * @param repo Nome do repositório (ex: 'Atolada-anchor')
 * @param branch Nome da branch destino (ex: 'rustshield-patch-232815-uidm' ou 'main')
 * @param filesToCommit Array com { path, content } para cada arquivo
 * @param options Opções como token PAT personalizado e mensagem do commit
 */
export async function pushMultipleFilesToBranch(
  owner: string,
  repo: string,
  branch: string,
  filesToCommit: FileToCommit[],
  options: PushMultipleFilesOptions = {}
): Promise<string> {
  if (!filesToCommit || filesToCommit.length === 0) {
    throw new Error("Nenhum arquivo fornecido para o commit em lote.");
  }

  const octokit = getOctokitClient(options.token);
  const commitMessage =
    options.commitMessage ||
    "fix(security): remediação automática de dependências e memory safety via RustShield";
  const force = options.force ?? true;

  try {
    console.log(
      `[GitHub Batch Git Data API] Iniciando push atômico de ${filesToCommit.length} arquivo(s) em ${owner}/${repo}@${branch}...`
    );

    // 1. Obter o SHA do commit atual da branch
    const { data: refData } = await octokit.git.getRef({
      owner,
      repo,
      ref: `heads/${branch}`,
    });
    const latestCommitSha = refData.object.sha;

    // Obter a árvore (Tree) do commit atual
    const { data: commitData } = await octokit.git.getCommit({
      owner,
      repo,
      commit_sha: latestCommitSha,
    });
    const baseTreeSha = commitData.tree.sha;

    // 2. Criar os Blobs (arquivos) e montar a nova árvore
    const treeItems = await Promise.all(
      filesToCommit.map(async (file) => {
        // Normaliza o caminho (remove barras no início ou ./)
        const normalizedPath = file.path.trim().replace(/^\/+/, '').replace(/^\.\//, '');

        const { data: blobData } = await octokit.git.createBlob({
          owner,
          repo,
          content: file.content,
          encoding: "utf-8",
        });

        return {
          path: normalizedPath,
          mode: "100644" as const, // Modo padrão para arquivos de texto
          type: "blob" as const,
          sha: blobData.sha,
        };
      })
    );

    // 3. Criar a nova Tree
    const { data: newTree } = await octokit.git.createTree({
      owner,
      repo,
      base_tree: baseTreeSha,
      tree: treeItems,
    });

    // 4. Criar o novo Commit
    const { data: newCommit } = await octokit.git.createCommit({
      owner,
      repo,
      message: commitMessage,
      tree: newTree.sha,
      parents: [latestCommitSha],
    });

    // 5. Atualizar a branch (HEAD)
    await octokit.git.updateRef({
      owner,
      repo,
      ref: `heads/${branch}`,
      sha: newCommit.sha,
      force, // Força a atualização da branch para o novo commit
    });

    console.log(
      `[GitHub Batch Git Data API] Integração concluída! Todos os ${filesToCommit.length} arquivos foram enviados ao PR (Commit SHA: ${newCommit.sha}).`
    );
    return newCommit.sha;
  } catch (error) {
    console.error("[GitHub Batch Git Data API] Erro na integração com o GitHub API:", error);
    throw error;
  }
}
