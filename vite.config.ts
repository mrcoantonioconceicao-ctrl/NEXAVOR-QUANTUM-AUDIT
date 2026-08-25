import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import dotenv from 'dotenv';
import { defineConfig, type Plugin } from 'vite';
import express from 'express';
import { handleAnalyzeRepo, handleFetchGitHub, handleGetSystemMetrics } from './server/routes.js';

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

      app.get('/api/github/repo', (req, res) => {
        handleFetchGitHub(req as any, res as any);
      });

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
