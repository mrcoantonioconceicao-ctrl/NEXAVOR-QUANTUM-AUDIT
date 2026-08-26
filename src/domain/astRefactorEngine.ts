import { SupportedLanguage } from './types.ts';

export type AstNodeType =
  | 'UNSAFE_BLOCK'
  | 'UNWRAPPED_RESULT'
  | 'RAW_POINTER_DEREF'
  | 'CONCURRENCY_HAZARD'
  | 'TYPE_SAFETY_VIOLATION'
  | 'DEPRECATED_OBSOLETE_SYNTAX'
  | 'UNSANITIZED_INPUT_INJECTION'
  | 'RESOURCE_LEAK_NO_RAII';

export interface AstNodeLocation {
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

export interface AstViolationNode {
  nodeId: string;
  type: AstNodeType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  location: AstNodeLocation;
  codeSnippet: string;
  cwe?: string;
  recommendation: string;
  structuralConstraint: string; // Regra estrutural inegociável enviada à IA
}

export interface AstTreeSummaryNode {
  id: string;
  label: string;
  kind: 'function' | 'struct' | 'module' | 'unsafe_block' | 'error_handling' | 'concurrency';
  lineStart: number;
  lineEnd: number;
  hasViolations: boolean;
  children?: AstTreeSummaryNode[];
}

export interface AstAnalysisReport {
  id: string;
  filePath: string;
  language: SupportedLanguage | string;
  totalLines: number;
  astNodesCount: number;
  criticalViolationsCount: number;
  highViolationsCount: number;
  violations: AstViolationNode[];
  astTreeSummary: AstTreeSummaryNode[];
  originalContent: string;
  estimatedRefactorHours: number;
  timestamp: string;
}

/**
 * Bounded Context de Análise Sintática Abstrata (AST)
 * Motor determinístico que processa a estrutura do código e extrai os nós com violações
 * para servirem de restrição absoluta durante o raciocínio da IA Generativa (Gemini).
 */
export class AstRefactorEngine {
  public static analyzeFile(filePath: string, content: string, langHint?: string): AstAnalysisReport {
    const language = langHint || this.detectLanguageFromPath(filePath);
    const lines = content.split('\n');
    const violations: AstViolationNode[] = [];
    const astTreeSummary: AstTreeSummaryNode[] = [];

    let nodeCounter = 1;

    // Detectors por Análise Estrutural AST
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const lineNumber = i + 1;

      // 1. Rust / C / Go: Bloco Unsafe ou Unsafe Pointer
      if (
        lineText.includes('unsafe {') ||
        lineText.includes('unsafe fn') ||
        lineText.includes('unsafe.Pointer') ||
        lineText.includes('std::mem::transmute')
      ) {
        let endLine = lineNumber;
        // Tenta encontrar o fechamento de chaves
        let openBrackets = 0;
        for (let j = i; j < lines.length; j++) {
          if (lines[j].includes('{')) openBrackets++;
          if (lines[j].includes('}')) openBrackets--;
          if (openBrackets === 0 && j > i) {
            endLine = j + 1;
            break;
          }
        }
        if (endLine === lineNumber) endLine = Math.min(lineNumber + 4, lines.length);

        const snippet = lines.slice(i, endLine).join('\n');
        violations.push({
          nodeId: `AST-NODE-${nodeCounter++}`,
          type: 'UNSAFE_BLOCK',
          severity: 'CRITICAL',
          title: 'Bloco Unsafe com Risco de Memory Safety / Undefined Behavior',
          location: { startLine: lineNumber, endLine },
          codeSnippet: snippet,
          cwe: 'CWE-119 / CWE-242',
          recommendation: 'Substitua operações de memória brutas por abstrações seguras e encapsuladas com RAII, Result/Option e Tipos do Domínio.',
          structuralConstraint: 'ESTRUTURA DE DADOS SEGURA: O código refatorado DEVE eliminar o bloco unsafe e manter compatibilidade de assinatura.',
        });
      }

      // 2. Unwrapped Result / Panic Prone (.unwrap(), .expect(), panic!(), unhandled promises)
      if (
        (lineText.includes('.unwrap(') || lineText.includes('.expect(') || lineText.includes('panic!(')) &&
        !lineText.trim().startsWith('//')
      ) {
        violations.push({
          nodeId: `AST-NODE-${nodeCounter++}`,
          type: 'UNWRAPPED_RESULT',
          severity: 'HIGH',
          title: 'Invocação Não Protegida .unwrap() / .expect() / panic!() em Código Principal',
          location: { startLine: lineNumber, endLine: lineNumber },
          codeSnippet: lineText.trim(),
          cwe: 'CWE-391 / CWE-754',
          recommendation: 'Substitua por propagação explícita de erro utilizando o operador (?) ou tratamento Result<T, DomainError>.',
          structuralConstraint: 'TRATAMENTO EXPLICITO DE ERROS: A refatoração NÃO pode lançar exceções não tratadas nem pânicos em tempo de execução.',
        });
      }

      // 3. Concorrência e Estado Compartilhado Mutável (static mut, raw Mutex lock sem guard, unhandled goroutine race)
      if (
        (lineText.includes('static mut') || lineText.includes('Arc::new(Mutex::new') || lineText.includes('go func(')) &&
        !lineText.trim().startsWith('//')
      ) {
        violations.push({
          nodeId: `AST-NODE-${nodeCounter++}`,
          type: 'CONCURRENCY_HAZARD',
          severity: 'CRITICAL',
          title: 'Perigo de Concorrência e Data Race em Estado Mutável Compartilhado',
          location: { startLine: lineNumber, endLine: Math.min(lineNumber + 3, lines.length) },
          codeSnippet: lineText.trim(),
          cwe: 'CWE-362 / CWE-662',
          recommendation: 'Encapsule o estado em estruturas atômicas (AtomicBool/AtomicU64), Tokio RwLock isolado ou Canais (mpsc/channels).',
          structuralConstraint: 'THREAD SAFETY: Garanta concorrência segura com Send + Sync e abstração assíncrona não bloqueante.',
        });
      }

      // 4. Injeção de Código / Concatenação SQL / Shell / Path Traversal
      if (
        (lineText.includes('exec(') || lineText.includes('execSync(') || lineText.includes('system(') || lineText.includes('SELECT ') || lineText.includes('os.system')) &&
        (lineText.includes('+') || lineText.includes('${') || lineText.includes('format!')) &&
        !lineText.trim().startsWith('//')
      ) {
        violations.push({
          nodeId: `AST-NODE-${nodeCounter++}`,
          type: 'UNSANITIZED_INPUT_INJECTION',
          severity: 'CRITICAL',
          title: 'Entrada Não Sanitizada com Risco de Injeção de Comandos ou SQL',
          location: { startLine: lineNumber, endLine: lineNumber },
          codeSnippet: lineText.trim(),
          cwe: 'CWE-78 / CWE-89',
          recommendation: 'Utilize consultas parametrizadas (Prepared Statements) e execFile com argumentos parametrizados em vetor.',
          structuralConstraint: 'PARAMETRIZAÇÃO: Elimine qualquer concatenação de strings em comandos do sistema ou consultas SQL.',
        });
      }

      // 5. Violador de Tipagem TypeScript/Go (any, interface{}, raw dynamic casting)
      if (
        (lineText.includes(': any') || lineText.includes('interface{}') || lineText.includes('as any')) &&
        !lineText.trim().startsWith('//')
      ) {
        violations.push({
          nodeId: `AST-NODE-${nodeCounter++}`,
          type: 'TYPE_SAFETY_VIOLATION',
          severity: 'MEDIUM',
          title: 'Violador de Segurança de Tipos (Uso de `any` ou `interface{}` dinâmico)',
          location: { startLine: lineNumber, endLine: lineNumber },
          codeSnippet: lineText.trim(),
          cwe: 'CWE-843',
          recommendation: 'Substitua por interfaces tipadas estaticamente, Generics ou Value Objects DDD.',
          structuralConstraint: 'TIPAGEM ESTRITA: Imponha tipagem forte e imutável para os contratos de entrada e saída.',
        });
      }
    }

    // Gerar Resumo Sintático de Árvore (AST Structural Hierarchy)
    let currentModule: AstTreeSummaryNode = {
      id: 'AST-ROOT-MODULE',
      label: `Módulo Fonte (${filePath})`,
      kind: 'module',
      lineStart: 1,
      lineEnd: lines.length,
      hasViolations: violations.length > 0,
      children: [],
    };

    // Identificar funções/métodos no arquivo
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (
        line.includes('fn ') ||
        line.includes('function ') ||
        line.includes('func ') ||
        line.includes('pub fn ') ||
        line.includes('async fn ')
      ) {
        const fnNameMatch = line.match(/(?:fn|function|func)\s+([a-zA-Z0-9_]+)/);
        const fnName = fnNameMatch ? fnNameMatch[1] : `function_line_${i + 1}`;
        const hasNodeInFn = violations.some((v) => v.location.startLine >= i + 1 && v.location.startLine <= i + 15);

        currentModule.children?.push({
          id: `AST-FN-${i + 1}`,
          label: `função ${fnName}()`,
          kind: 'function',
          lineStart: i + 1,
          lineEnd: Math.min(i + 20, lines.length),
          hasViolations: hasNodeInFn,
        });
      }
    }

    astTreeSummary.push(currentModule);

    const criticals = violations.filter((v) => v.severity === 'CRITICAL').length;
    const highs = violations.filter((v) => v.severity === 'HIGH').length;

    // Cálculo do esforço de engenharia estimado (horas economizadas)
    const estimatedRefactorHours = Math.max(1.5, criticals * 3.5 + highs * 2.0 + violations.length * 0.8);

    return {
      id: `AST-REF-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      filePath,
      language,
      totalLines: lines.length,
      astNodesCount: violations.length,
      criticalViolationsCount: criticals,
      highViolationsCount: highs,
      violations,
      astTreeSummary,
      originalContent: content,
      estimatedRefactorHours: Number(estimatedRefactorHours.toFixed(1)),
      timestamp: new Date().toISOString(),
    };
  }

  private static detectLanguageFromPath(filePath: string): SupportedLanguage | string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'rs':
        return 'Rust';
      case 'ts':
      case 'tsx':
        return 'TypeScript';
      case 'js':
      case 'jsx':
        return 'JavaScript';
      case 'go':
        return 'Go';
      case 'py':
        return 'Python';
      case 'c':
      case 'h':
        return 'C';
      case 'cpp':
      case 'hpp':
        return 'C++';
      case 'java':
        return 'Java';
      case 'sol':
        return 'Solidity';
      default:
        return 'Polyglot';
    }
  }
}
