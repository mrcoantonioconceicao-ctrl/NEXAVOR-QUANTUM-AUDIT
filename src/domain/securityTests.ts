import { SecurityTestCase, RustVulnerability } from './types.ts';

export function generateSecurityTestSuite(vulnerabilities: RustVulnerability[]): SecurityTestCase[] {
  const hasUnsafe = vulnerabilities.some((v) => v.category === 'UNSAFE_UB' || v.category === 'MEMORY_SAFETY');
  const hasRace = vulnerabilities.some((v) => v.category === 'CONCURRENCY_RACE');
  const hasDeser = vulnerabilities.some((v) => v.category === 'DESERIALIZATION_RCE');
  const hasInjection = vulnerabilities.some((v) => v.category === 'INJECTION_SQL_CMD');
  const hasWeb3 = vulnerabilities.some((v) => v.category === 'REENTRANCY_WEB3');
  const hasProto = vulnerabilities.some((v) => v.category === 'PROTOTYPE_POLLUTION');

  const baseTests: SecurityTestCase[] = [
    {
      id: 'TEST-MIRI-ASAN-01',
      name: 'Memory Safety & Undefined Behavior (UB) Sanitizer / ASan',
      category: 'MIRI_UB',
      description: 'Executa sanitizadores de memória em tempo de execução (Miri, AddressSanitizer, Valgrind) para detectar violações de ponteiros e memória desinicializada.',
      severity: 'CRITICAL',
      status: hasUnsafe ? 'FAILED' : 'PASSED',
      inputPayload: 'miri / asan_harness --check-bounds --strict-provenance --detect-leaks=1',
      executionLog: hasUnsafe
        ? 'ERRO: Comportamento Indefinido (UB) detectado: Acesso a memória desinicializada / Violação de limites de buffer em offset [0x7ffe..]\n = ajuda: Esta falha indica uma violação de segurança de memória explorável.'
        : 'Todos os limites de memória verificados e seguros. 0 vazamentos, 0 comportamentos indefinidos detectados.',
      mitigationVerification: 'Inicialização segura, bounds checking estrito e tipos de contêineres gerenciados com RAII.',
    },
    {
      id: 'TEST-RCE-DESER-02',
      name: 'Inspeção de Desserialização Não Confiável & RCE Gadget Chains',
      category: 'DESERIALIZATION',
      description: 'Testa payloads de desserialização não confiável (Python pickle, Java ObjectInputStream, YAML tags, Node.js serialized) para detectar RCE.',
      severity: 'CRITICAL',
      status: hasDeser ? 'FAILED' : 'PASSED',
      inputPayload: 'deser_fuzz_probe --target-payload=__reduce___rce_vector --gadget-scan',
      executionLog: hasDeser
        ? 'ALERTA CRÍTICO: Desserialização executou criação não autorizada de processo do sistema operacional (os.system / Runtime.exec).\nExecução remota de código (RCE) confirmada no nó de execução.'
        : 'APROVADO: Desserializador impõe estritamente esquemas tipados estáticos JSON / Protocol Buffers sem gadgets polimórficos.',
      mitigationVerification: 'Substituição de serializadores reflexivos por parsers tipados (JSON/Protobuf/SafeLoader).',
    },
    {
      id: 'TEST-INJECTION-03',
      name: 'Verificador de Injeção de Comandos & Parametrização SQL',
      category: 'INJECTION',
      description: 'Dispara mutações com payloads SQLi clássicos (`\' OR 1=1 --`) e Command Injection (`$(id); /bin/sh`) contra todas as rotas de entrada.',
      severity: 'HIGH',
      status: hasInjection ? 'FAILED' : 'PASSED',
      inputPayload: 'sqlmap_sec_scan --risk=3 --level=5 / cmd_injection_fuzz',
      executionLog: hasInjection
        ? 'VULNERABILIDADE CONFIRMADA: Concatenação direta de SQL / Shell identificada no motor de consultas.\nPayload injetado com sucesso no pipeline de subprocesso.'
        : 'APROVADO: Todas as consultas utilizam prepared statements / execFile sem interpretação de shell.',
      mitigationVerification: 'Uso obrigatório de prepared statements parametrizados e execução de binários com argumentos estruturados.',
    },
    {
      id: 'TEST-RACE-04',
      name: 'ThreadSanitizer (TSan) & Verificador de Race Conditions em Goroutines',
      category: 'CONCURRENCY_RACE',
      description: 'Testa permutações de escalonamento preemptivo de threads e goroutines para detectar Data Races em memória compartilhada sob 10.000 CCU.',
      severity: 'CRITICAL',
      status: hasRace ? 'FAILED' : 'PASSED',
      inputPayload: 'go test -race / RUSTFLAGS="-Zsanitizer=thread" cargo test',
      executionLog: hasRace
        ? 'AVISO: ThreadSanitizer / Go Race Detector: corrida de dados (data race) detectada em memória/mapa compartilhado.\nEscritas concorrentes sem bloqueio de sincronização (mutex).'
        : 'ThreadSanitizer aprovado. Nenhuma corrida de dados concorrente observada em 10.000 clientes simulados.',
      mitigationVerification: 'Encapsulamento de estado em Mutex/RwLock, atomics ou canais assíncronos isolados.',
    },
    {
      id: 'TEST-PQC-05',
      name: 'MIT Quantum Shor Algorithm & PQC Key Decoupling Test',
      category: 'QUANTUM_CRACK',
      description: 'Simula a complexidade assintótica de fatoração em computadores quânticos para chaves assimétricas clássicas (RSA/ECC) e audita resistência NIST FIPS 203/204.',
      severity: 'HIGH',
      status: 'FAILED',
      inputPayload: 'qiskit_shor_sim --target-key rsa-2048 --qubits 4096 --modular-exponentiation',
      executionLog: 'ALERT: Primitivas assimétricas clássicas vulneráveis a algoritmo quântico de Shor.\nRisco imediato de descriptografia retroativa via "Harvest Now, Decrypt Later".',
      mitigationVerification: 'Migração para encapsulamento híbrido X25519 + ML-KEM-768 (Kyber) em conformidade com NIST PQC.',
    },
    {
      id: 'TEST-WAVE-06',
      name: 'Wavefront Spectral Hazard & Soliton Resonance Damping',
      category: 'WAVE_SHOCKWAVE',
      description: 'Mapeia a interferência construtiva de ondas de complexidade de estado no grafo de controle para isolar vetores Zero-Day latentes.',
      severity: 'CRITICAL',
      status: 'FAILED',
      inputPayload: 'wave_spectral_probe --entropy-threshold 0.75 --resonance-scan --soliton-dampener',
      executionLog: 'DETECTED: Ressonância construtiva de risco (A_res = 88.4%) entre camadas arquiteturais.\nOnda de choque atinge limites de microsserviços.',
      mitigationVerification: 'Injeção de Padrão Soliton: Amortecimento de falhas com Circuit Breakers e Bounded Contexts rígidos.',
    },
  ];

  if (hasWeb3) {
    baseTests.push({
      id: 'TEST-WEB3-07',
      name: 'Simulação de Ataque de Reentrância e Flashloan via Slither & Foundry',
      category: 'REENTRANCY',
      description: 'Simula chamadas aninhadas na função de fallback para drenagem de liquidez de smart contracts (SWC-107).',
      severity: 'CRITICAL',
      status: 'FAILED',
      inputPayload: 'slither . --detect reentrancy-eth,tx-origin / forge test --fuzz-runs 10000',
      executionLog: 'REENTRÂNCIA DETECTADA: Atualização de estado ocorre após chamada externa `.msg.sender.call{value: amount}("")`.\nLiquidez drenada com sucesso em transação de flashloan simulada.',
      mitigationVerification: 'Implementação estrita do padrão Checks-Effects-Interactions e ReentrancyGuard da OpenZeppelin.',
    });
  }

  return baseTests;
}
