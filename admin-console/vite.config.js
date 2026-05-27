import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/** Strip the CSP meta tag during development so Vite HMR inline scripts work. */
function stripCspInDev() {
  return {
    name: 'strip-csp-dev',
    transformIndexHtml(html, ctx) {
      if (ctx.server) {
        return html.replace(/<meta http-equiv="Content-Security-Policy"[^>]*\/?>\n?/, '');
      }
      return html;
    },
  };
}

export default defineConfig({
  plugins: [react(), stripCspInDev()],
  root: '.',
  base: '/admin/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    reportCompressedSize: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (/[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/.test(id)) {
              return 'vendor';
            }
            if (/[\\/]node_modules[\\/](recharts|d3-[^/\\]+|victory-vendor)[\\/]/.test(id)) {
              return 'charts';
            }
          }
          return undefined;
        },
      },
    },
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    setupFiles: ['./src/__tests__/setup.js'],
    include: ['src/**/*.test.{js,jsx}'],
    css: false,
    testTimeout: 30000,
    hookTimeout: 30000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      include: ['src/**/*.{js,jsx}'],
      exclude: [
        'src/**/*.test.{js,jsx}',
        'src/__tests__/**',
        'src/main.jsx',
        'src/api.js',
      ],
      thresholds: {
        statements: 60,
        branches: 55,
        functions: 55,
        lines: 60,
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
    historyApiFallback: true,
  },
});
