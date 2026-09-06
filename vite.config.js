import { defineConfig } from 'vite';

export default defineConfig({
    root: 'public',
    server: {
        port: 30303,
        proxy: {
            '/api': 'http://localhost:3333',
            '/socket.io': {
                target: 'http://localhost:3333',
                ws: true,
            },
            '/uploads': 'http://localhost:3333',
        },
    },
    build: {
        outDir: '../dist',
        emptyOutDir: true,
    },
    resolve: {
        alias: {
            '@': '/js',
        },
    },
});
