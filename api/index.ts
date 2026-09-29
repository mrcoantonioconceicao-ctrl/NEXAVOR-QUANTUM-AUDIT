import express from 'express';
import dotenv from 'dotenv';
import {
  handleAnalyzeRepo,
  handleAstScan,
  handleFetchGitHub,
  handleGetSystemMetrics,
  handleOsvBatchProxy,
  handleCreateGitHubPullRequest,
  handleSuggestRustPatch,
  handleAstRefactor,
  handleCreateRefactorPullRequest,
  handleHybridRagQuery,
  handleQueryImpactGraph,
  handleExportCypher,
  handleSyncGraph,
  handleThreatIntelSearch,
} from '../server/routes.js';
import { mcpRouter } from '../server/mcpServer.js';
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
  handleGetLinkedRepos,
  handleSaveLinkedRepo,
  handleDeleteLinkedRepo,
  handleUpdateLinkedRepo,
  handleSimulatePushReaudit,
} from '../server/webhooks.js';
import { handleBadgeSvg } from '../server/badgeGenerator.js';

dotenv.config();

const app = express();
app.use(express.json({ limit: '15mb' }));

// Health Check Endpoint
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'online',
    version: '2.5.0-serverless',
    platform: 'Vercel Serverless / Edge Compatible',
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/metrics', handleGetSystemMetrics);
app.use('/api', mcpRouter);

app.post('/api/rag/hybrid-query', handleHybridRagQuery);
app.post('/api/rag/impact-graph', handleQueryImpactGraph);
app.get('/api/rag/cypher-export', handleExportCypher);
app.post('/api/rag/graph-sync', handleSyncGraph);

app.post('/api/audit/threat-intel-search', handleThreatIntelSearch);
app.post('/api/threat-intel/search', handleThreatIntelSearch);

app.post('/api/audit/analyze', handleAnalyzeRepo);
app.post('/api/audit/ast-scan', handleAstScan);
app.post('/api/audit/suggest-rust-patch', handleSuggestRustPatch);
app.post('/api/audit/ast-refactor', handleAstRefactor);
app.post('/api/audit/osv-batch', handleOsvBatchProxy);
app.get('/api/github/repo', handleFetchGitHub);
app.post('/api/github/repo', handleFetchGitHub);
app.get('/api/github/fetch-repo', handleFetchGitHub);
app.post('/api/github/fetch-repo', handleFetchGitHub);
app.post('/api/github/create-pr', handleCreateGitHubPullRequest);
app.post('/api/github/pulls', handleCreateGitHubPullRequest);
app.post('/api/github/refactor-pr', handleCreateRefactorPullRequest);

app.get('/api/webhooks/configs', handleGetWebhookConfigs);
app.post('/api/webhooks/config', handleSaveWebhookConfig);
app.delete('/api/webhooks/config/:id', handleDeleteWebhookConfig);
app.get('/api/webhooks/deliveries', handleGetWebhookDeliveries);
app.post('/api/webhooks/github', handleIncomingGitHubWebhook);
app.post('/api/webhooks/simulate', handleSimulateWebhook);
app.get('/api/webhooks/stream', handleWebhookStream);

app.get('/api/linked-repos', handleGetLinkedRepos);
app.post('/api/linked-repos', handleSaveLinkedRepo);
app.delete('/api/linked-repos/:id', handleDeleteLinkedRepo);
app.patch('/api/linked-repos/:id', handleUpdateLinkedRepo);
app.post('/api/linked-repos/simulate-push', handleSimulatePushReaudit);

app.get('/api/webhooks/fuzz-alerts', handleGetFuzzAlerts);
app.post('/api/webhooks/fuzz-alert', handleFuzzCrashAlert);
app.post('/api/webhooks/simulate-fuzz-crash', handleSimulateFuzzCrashAlert);

app.get('/api/badge/shield.svg', handleBadgeSvg);
app.get('/api/badge/svg', handleBadgeSvg);

export default app;
