import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import basicSsl from '@vitejs/plugin-basic-ssl';

// https://vite.dev/config/
export default defineConfig({
    plugins: [react(), basicSsl()],
    server: {
        allowedHosts: ['home-dev.davidnewmon.com'],
        proxy: {
            '/api': {
                target: 'http://localhost:5002',
                changeOrigin: true,
            },
        },
    },
});
