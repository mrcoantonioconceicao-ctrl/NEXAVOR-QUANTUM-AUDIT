import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { handleAnalyzeRepo, handleFetchGitHub, handleGetSystemMetrics, handleOsvBatchProxy, handleCreateGitHubPullRequest, handleSuggestRustPatch, handleAstRefactor, handleCreateRefactorPullRequest } from './server/routes.js';
import {
  handleGetWebhookConfigs,
  handleSaveWebhookConfig,
  handleDeleteWebhookConfig,
  handleGetWebhookDeliveries,
  handleIncomingGitHubWebhook,
  handleSimulateWebhook,
  handleWebhookStream,
} from './server/webhooks.js';

import { handleBadgeSvg } from './server/badgeGenerator.js';

dotenv.config();


const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '15mb' }));

// Health check endpoint
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'online',
    version: '2.5.0-production',
    standards: ['DDD-Bounded-Context', 'SOA-Hexagonal', 'BPMN-2.0', 'Post-Quantum-ML-KEM', 'Wave-Theory-Soliton-ZeroDay'],
    environment: process.env.NODE_ENV || 'production',
    timestamp: new Date().toISOString(),
  });
});

// Real-time runtime telemetry metrics
app.get('/api/metrics', handleGetSystemMetrics);

// Real API Routes
app.post('/api/audit/analyze', handleAnalyzeRepo);
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

// Dynamic SVG Badge Generation Route
app.get('/api/badge/shield.svg', handleBadgeSvg);
app.get('/api/badge/svg', handleBadgeSvg);


// Serve static assets in production
const distPath = path.resolve(process.cwd(), 'dist');
app.use(express.static(distPath));

app.get('*', (_req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[Q-Audit Production Security Server] Running on http://localhost:${PORT}`);
});
