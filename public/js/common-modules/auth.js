export function getAuthHeaders() {
    const token = localStorage.getItem('ta_token');
    return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (token || '') };
}

export function checkAuth() {
    const token = localStorage.getItem('ta_token');
    if (!token) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

export function logout() {
    localStorage.removeItem('ta_uid');
    localStorage.removeItem('ta_token');
    localStorage.removeItem('ta_role');
    localStorage.removeItem('ta_is_admin');
    localStorage.removeItem('ta_is_manager');
    window.location.href = 'login.html';
}
