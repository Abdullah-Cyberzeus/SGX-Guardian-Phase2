import { defineConfig, type Plugin } from 'vite'
import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'

function pwaAssetManifest(): Plugin {
  return {
    name: 'sgx-pwa-asset-manifest',
    generateBundle(_, bundle) {
      const assets = Object.values(bundle)
        .map((entry) => `/${entry.fileName}`)
        .filter((fileName) => /\.(?:js|css|woff2?|png|jpg|jpeg|svg|webp|ico)$/i.test(fileName))
        .sort();
      this.emitFile({
        type: 'asset',
        fileName: 'asset-manifest.json',
        source: JSON.stringify({ assets }, null, 2),
      });
    },
  };
}

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version || 'dev'),
  },
  plugins: [
    // The React and Tailwind plugins are both required for Make, even if
    // Tailwind is not being actively used – do not remove them
    react(),
    tailwindcss(),
    pwaAssetManifest(),
  ],
  resolve: {
    alias: {
      // Alias @ to the src directory
      '@': path.resolve(__dirname, './src'),
    },
  },

  // File types to support raw imports. Never add .css, .tsx, or .ts files to this.
  assetsInclude: ['**/*.svg', '**/*.csv'],
  server: {
    // VITE_DEV_PORT / VITE_API_TARGET let you point this dev server at any
    // node (nodeA/B/C) without touching this file — see the three commands
    // in the project notes. Defaults preserve this branch's current setup.
    port: Number(process.env.VITE_DEV_PORT) || 3000,
    strictPort: true,

    proxy: {
      '/api/v1': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:8443',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
