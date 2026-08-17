const js = require('@eslint/js');
const prettier = require('eslint-plugin-prettier');

module.exports = [
    js.configs.recommended,
    {
        files: ['**/*.js'],
        ignores: ['node_modules/**', 'data/**', 'public/js/marked.min.js', '**/*.min.js'],
        plugins: {
            prettier,
        },
        rules: {
            'prettier/prettier': 'warn',
            'no-unused-vars': 'warn',
            'no-undef': 'off',
        },
    },
];
