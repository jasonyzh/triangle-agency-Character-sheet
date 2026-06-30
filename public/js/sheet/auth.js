import { S } from './state.js';

export function getAuthHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (S.token) headers['Authorization'] = `Bearer ${S.token}`;
    return headers;
}
