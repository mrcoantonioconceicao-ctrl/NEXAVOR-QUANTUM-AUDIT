export interface ClusterNode {
  id: string;
  name: string;
  role: 'INGESTION_GATEWAY' | 'AST_WORKER_POOL' | 'WAVE_PQC_ENGINE' | 'REDIS_SHARD' | 'PGBOUNCER_DB';
  status: 'HEALTHY' | 'SCALING' | 'DEGRADED';
  cpuPercent: number;
  memoryMb: number;
  throughputRps: number;
  activeConnections: number;
  region: string;
}

export interface ScaleMetrics {
  concurrentClients: number;
  requestsPerSecond: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  cacheHitRatioPercent: number;
  activeWorkerPods: number;
  maxWorkerPods: number;
  queueDepth: number;
  droppedPacketsPercent: number;
  memoryAllocatedMb: number;
  dbPoolUtilizationPercent: number;
  tokenBucketAllowedRps: number;
}

export interface EnterpriseScaleSpec {
  dimension: string;
  target10kCapacity: string;
  technologyStack: string;
  slaGenders: string;
  failoverStrategy: string;
}

export const ENTERPRISE_SCALE_SPECS: EnterpriseScaleSpec[] = [
  {
    dimension: 'Ingestão e Gateway de Tráfego',
    target10kCapacity: '10.000 Conexões Simultâneas HTTP/2 e gRPC (30.000 RPS Pico)',
    technologyStack: 'Envoy Gateway + NGINX Plus + Rust Axum Proxy com zero-copy buffer',
    slaGenders: 'Latência p95 < 25ms, Uptime 99.99%',
    failoverStrategy: 'BGP Anycast Multi-Region (US-East, EU-Central, SA-East)',
  },
  {
    dimension: 'Fila Assíncrona & Worker Pools',
    target10kCapacity: 'Processamento de 10.000 auditorias simultâneas sem bloqueio',
    technologyStack: 'Redis Cluster 7.2 Sharded Streams + Tokio Async Workers em Rust',
    slaGenders: 'Taxa de esvaziamento de fila > 1.200 jobs/segundo',
    failoverStrategy: 'Auto-scaling HPA Kubernetes de 16 a 128 pods em 15 segundos',
  },
  {
    dimension: 'Camada de Caching Distribuído (L1/L2/L3)',
    target10kCapacity: '99.2% de Cache Hit para ASTs e Caches de Vulnerabilidades',
    technologyStack: 'L1: Moka LRU In-Memory (Rust) | L2: Redis Multi-AZ | L3: Cloudflare Edge',
    slaGenders: 'Tempo de resposta de cache L1 < 0.4ms | L2 < 2.1ms',
    failoverStrategy: 'Cache invalidation via pub/sub com fallback gracioso para L2 replica',
  },
  {
    dimension: 'Banco de Dados & Connection Pooling',
    target10kCapacity: '10.000 Conexões de Clientes multiplexadas para 120 conexões PostgreSQL',
    technologyStack: 'PgBouncer Transaction Pooling + PostgreSQL 16 com Particionamento Hash',
    slaGenders: 'Pool allocation latency < 1.2ms, 0 connection drops',
    failoverStrategy: 'Patroni HA com quorum Raft e failover sub-3-segundos',
  },
  {
    dimension: 'Isolamento Multi-Tenant & Segurança',
    target10kCapacity: '10.000 Tenants Corporativos com Sandbox Criptográfico Rigoroso',
    technologyStack: 'gVisor Sandboxed Containers + Namespaces e mTLS Spire/Istio',
    slaGenders: 'Zero vazamento cruzado de ASTs ou segredos (SOC 2 Type II / ISO 27001)',
    failoverStrategy: 'Circuit breaker imediato ao detectar anomalia de tenant',
  },
];

export function generateInitialClusterNodes(): ClusterNode[] {
  return [
    {
      id: 'node-gw-01',
      name: 'gw-ingress-us-east-01',
      role: 'INGESTION_GATEWAY',
      status: 'HEALTHY',
      cpuPercent: 32,
      memoryMb: 820,
      throughputRps: 6400,
      activeConnections: 2500,
      region: 'us-east-1a',
    },
    {
      id: 'node-gw-02',
      name: 'gw-ingress-us-east-02',
      role: 'INGESTION_GATEWAY',
      status: 'HEALTHY',
      cpuPercent: 35,
      memoryMb: 850,
      throughputRps: 6800,
      activeConnections: 2600,
      region: 'us-east-1b',
    },
    {
      id: 'node-ast-pool',
      name: 'rust-ast-worker-hpa (64 pods)',
      role: 'AST_WORKER_POOL',
      status: 'HEALTHY',
      cpuPercent: 48,
      memoryMb: 4200,
      throughputRps: 18500,
      activeConnections: 4900,
      region: 'multi-az-cluster',
    },
    {
      id: 'node-wave-pqc',
      name: 'wave-pqc-engine-accelerator',
      role: 'WAVE_PQC_ENGINE',
      status: 'HEALTHY',
      cpuPercent: 42,
      memoryMb: 2800,
      throughputRps: 12000,
      activeConnections: 3100,
      region: 'multi-az-cluster',
    },
    {
      id: 'node-redis-cluster',
      name: 'redis-shard-master-cluster',
      role: 'REDIS_SHARD',
      status: 'HEALTHY',
      cpuPercent: 24,
      memoryMb: 16400,
      throughputRps: 28000,
      activeConnections: 10000,
      region: 'us-east-1',
    },
    {
      id: 'node-pgbouncer',
      name: 'pgbouncer-pool-ha (x4 instances)',
      role: 'PGBOUNCER_DB',
      status: 'HEALTHY',
      cpuPercent: 18,
      memoryMb: 1200,
      throughputRps: 14200,
      activeConnections: 10000,
      region: 'us-east-1',
    },
  ];
}

export function computeScaleMetricsForClients(clientCount: number): ScaleMetrics {
  // Linear & sub-linear algorithmic modeling for 10k enterprise readiness
  const factor = clientCount / 10000;
  const requestsPerSecond = Math.round(clientCount * 2.85 + Math.random() * 200);
  const p50LatencyMs = +(5.2 + factor * 2.1).toFixed(1);
  const p95LatencyMs = +(14.5 + factor * 6.4).toFixed(1);
  const p99LatencyMs = +(28.0 + factor * 12.5).toFixed(1);
  const cacheHitRatioPercent = +(99.4 - factor * 0.5).toFixed(1);
  const activeWorkerPods = Math.max(12, Math.min(128, Math.round(16 + factor * 80)));
  const queueDepth = Math.max(0, Math.round(factor * 34));
  const droppedPacketsPercent = 0.0;
  const memoryAllocatedMb = Math.round(1800 + factor * 14500);
  const dbPoolUtilizationPercent = Math.round(22 + factor * 54);
  const tokenBucketAllowedRps = 35000;

  return {
    concurrentClients: clientCount,
    requestsPerSecond,
    p50LatencyMs,
    p95LatencyMs,
    p99LatencyMs,
    cacheHitRatioPercent,
    activeWorkerPods,
    maxWorkerPods: 128,
    queueDepth,
    droppedPacketsPercent,
    memoryAllocatedMb,
    dbPoolUtilizationPercent,
    tokenBucketAllowedRps,
  };
}

export const KUBERNETES_HELM_BLUEPRINT = `# RustShield Enterprise 10,000 Clients HPA & Cluster Blueprint
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustshield-audit-engine
  namespace: security-enterprise
  labels:
    app.kubernetes.io/name: rustshield-engine
    tier: high-concurrency-backend
spec:
  replicas: 32 # Min base replicas for 10k CCU
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 0
  selector:
    matchLabels:
      app: rustshield-engine
  template:
    metadata:
      labels:
        app: rustshield-engine
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      containers:
      - name: audit-worker
        image: gcr.io/rustshield-prod/engine:v2.5.0-hardened
        imagePullPolicy: IfNotPresent
        resources:
          requests:
            cpu: "1000m"
            memory: "512Mi"
          limits:
            cpu: "4000m"
            memory: "2048Mi"
        env:
        - name: RUST_LOG
          value: "info,rustshield=debug"
        - name: TOKIO_WORKER_THREADS
          value: "8"
        - name: REDIS_CLUSTER_URLS
          value: "redis-node-1.cache:6379,redis-node-2.cache:6379,redis-node-3.cache:6379"
        - name: DATABASE_POOL_MAX_SIZE
          value: "30"
        readinessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 2
          periodSeconds: 5
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rustshield-engine-hpa
  namespace: security-enterprise
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rustshield-audit-engine
  minReplicas: 16
  maxReplicas: 128
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 65
  - type: External
    external:
      metric:
        name: redis_queue_depth_pending_jobs
      target:
        type: Value
        averageValue: "50"
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rustshield-edge-ingress
  annotations:
    kubernetes.io/ingress.class: "envoy"
    envoy.ingress.kubernetes.io/client-max-body-size: "50m"
    envoy.ingress.kubernetes.io/rate-limit: "token-bucket-10k-ccu"
spec:
  rules:
  - host: audit.rustshield.internal
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rustshield-audit-engine-svc
            port:
              number: 3000
`;
