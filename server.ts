import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { handleAnalyzeRepo, handleAstScan, handleFetchGitHub, handleGetSystemMetrics, handleOsvBatchProxy, handleCreateGitHubPullRequest, handleSuggestRustPatch, handleAstRefactor, handleCreateRefactorPullRequest, handleMcp, handleHybridRagQuery, handleQueryImpactGraph, handleExportCypher, handleSyncGraph } from './server/routes';

import {
  handleGetWebhookConfigs,
  handleSaveWebhookConfig,
  handleDeleteWebhookConfig,
  handleGetWebhookDeliveries,
  handleIncomingGitHubWebhook,
  handleSimulateWebhook,
  handleWebhookStream,
  handleGetFuzzAlerts,
  handleFuzzCrashAlert,
  handleSimulateFuzzCrashAlert,
} from './server/webhooks';

import { handleBadgeSvg } from './server/badgeGenerator';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '15mb' }));

  // Health check endpoint
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'online',
      version: '2.5.0-production',
      standards: ['DDD-Bounded-Context', 'SOA-Hexagonal', 'BPMN-2.0', 'Post-Quantum-ML-KEM', 'Wave-Theory-Soliton-ZeroDay'],
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    });
  });

  // Real-time runtime telemetry metrics
  app.get('/api/metrics', handleGetSystemMetrics);

  // MCP Protocol Route for IDEs and AI Assistants
  app.post('/api/mcp', handleMcp);

  // Hybrid RAG (Vector RAG + GraphRAG) & Knowledge Graph Endpoints
  app.post('/api/rag/hybrid-query', handleHybridRagQuery);
  app.post('/api/rag/impact-graph', handleQueryImpactGraph);
  app.get('/api/rag/cypher-export', handleExportCypher);
  app.post('/api/rag/graph-sync', handleSyncGraph);

  // Real API Routes
  app.post('/api/audit/analyze', handleAnalyzeRepo);
  app.post('/api/audit/ast-scan', handleAstScan);
  app.post('/api/audit/suggest-rust-patch', handleSuggestRustPatch);
  app.post('/api/audit/ast-refactor', handleAstRefactor);
  app.post('/api/audit/osv-batch', handleOsvBatchProxy);
  app.get('/api/github/repo', handleFetchGitHub);
  app.post('/api/github/create-pr', handleCreateGitHubPullRequest);
  app.post('/api/github/pulls', handleCreateGitHubPullRequest);
  app.post('/api/github/refactor-pr', handleCreateRefactorPullRequest);

  // Webhook Configuration & Real-time Integration Routes
  app.get('/api/webhooks/configs', handleGetWebhookConfigs);
  app.post('/api/webhooks/config', handleSaveWebhookConfig);
  app.delete('/api/webhooks/config/:id', handleDeleteWebhookConfig);
  app.get('/api/webhooks/deliveries', handleGetWebhookDeliveries);
  app.post('/api/webhooks/github', handleIncomingGitHubWebhook);
  app.post('/api/webhooks/simulate', handleSimulateWebhook);
  app.get('/api/webhooks/stream', handleWebhookStream);

  // Cargo-Fuzz Continuous CI/CD Memory Safety Alert Endpoints
  app.get('/api/webhooks/fuzz-alerts', handleGetFuzzAlerts);
  app.post('/api/webhooks/fuzz-alert', handleFuzzCrashAlert);
  app.post('/api/webhooks/simulate-fuzz-crash', handleSimulateFuzzCrashAlert);

  // Dynamic SVG Badge Generation Route
  app.get('/api/badge/shield.svg', handleBadgeSvg);
  app.get('/api/badge/svg', handleBadgeSvg);

  // Vite middleware for development / Static files in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));

    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Q-Audit Production Security Server] Running on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[Server Startup Error]', err);
});

