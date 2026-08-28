import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import dotenv from 'dotenv';
import { defineConfig, type Plugin } from 'vite';
import express from 'express';
import {
  handleAnalyzeRepo,
  handleFetchGitHub,
  handleGetSystemMetrics,
  handleOsvBatchProxy,
  handleCreateGitHubPullRequest,
  handleSuggestRustPatch,
  handleAstRefactor,
  handleCreateRefactorPullRequest,
} from './server/routes.js';
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

function apiServerPlugin(): Plugin {
  return {
    name: 'api-server-plugin',
    configureServer(server) {
      const app = express();
      app.use(express.json({ limit: '15mb' }));

      app.get('/api/health', (_req, res) => {
        res.json({
          status: 'online',
          version: '2.5.0-quantum',
          standards: ['DDD-Bounded-Context', 'SOA-Hexagonal', 'BPMN-2.0', 'Post-Quantum-ML-KEM', 'Wave-Theory-Soliton-ZeroDay'],
          environment: 'development',
          timestamp: new Date().toISOString(),
        });
      });

      app.get('/api/metrics', (req, res) => {
        handleGetSystemMetrics(req as any, res as any);
      });

      app.post('/api/audit/analyze', (req, res) => {
        handleAnalyzeRepo(req as any, res as any);
      });

      app.post('/api/audit/suggest-rust-patch', (req, res) => {
        handleSuggestRustPatch(req as any, res as any);
      });

      app.post('/api/audit/ast-refactor', (req, res) => {
        handleAstRefactor(req as any, res as any);
      });

      app.post('/api/audit/osv-batch', (req, res) => {
        handleOsvBatchProxy(req as any, res as any);
      });

      app.get('/api/github/repo', (req, res) => {
        handleFetchGitHub(req as any, res as any);
      });

      // GitHub Pull Requests endpoints
      app.post('/api/github/create-pr', (req, res) => {
        handleCreateGitHubPullRequest(req as any, res as any);
      });

      app.post('/api/github/pulls', (req, res) => {
        handleCreateGitHubPullRequest(req as any, res as any);
      });

      app.post('/api/github/refactor-pr', (req, res) => {
        handleCreateRefactorPullRequest(req as any, res as any);
      });

      // Webhooks & badges
      app.get('/api/webhooks/configs', (req, res) => handleGetWebhookConfigs(req as any, res as any));
      app.post('/api/webhooks/config', (req, res) => handleSaveWebhookConfig(req as any, res as any));
      app.delete('/api/webhooks/config/:id', (req, res) => handleDeleteWebhookConfig(req as any, res as any));
      app.get('/api/webhooks/deliveries', (req, res) => handleGetWebhookDeliveries(req as any, res as any));
      app.post('/api/webhooks/github', (req, res) => handleIncomingGitHubWebhook(req as any, res as any));
      app.post('/api/webhooks/simulate', (req, res) => handleSimulateWebhook(req as any, res as any));
      app.get('/api/webhooks/stream', (req, res) => handleWebhookStream(req as any, res as any));

      app.get('/api/badge/shield.svg', (req, res) => handleBadgeSvg(req as any, res as any));
      app.get('/api/badge/svg', (req, res) => handleBadgeSvg(req as any, res as any));

      server.middlewares.use(app);
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), apiServerPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      port: 3000,
      host: '0.0.0.0',
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
