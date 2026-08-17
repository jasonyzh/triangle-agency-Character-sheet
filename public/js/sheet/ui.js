export function showToast(msg, type = 'success') {
    const m = document.getElementById('status-msg');
    m.innerHTML = type === 'error' ? `<i class="fas fa-exclamation-circle"></i> ${msg}` : `<i class="fas fa-save"></i> ${msg}`;
    m.className = type === 'error' ? 'error' : 'success';
    m.style.display = 'block';
    setTimeout(() => m.style.display = 'none', 2500);
}

export function setRandomVars(el) {
    el.style.setProperty('--r1', Math.random());
    el.style.setProperty('--r2', Math.random());
    el.style.setProperty('--r3', Math.random());
}

export function escapeHtmlText(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export function preventWheelPenetration(e) {
    const target = e.target;
    const body = document.getElementById('assessmentBody');

    if (body && body.contains(target)) {
        const scrollTop = body.scrollTop;
        const scrollHeight = body.scrollHeight;
        const clientHeight = body.clientHeight;
        const delta = e.deltaY;

        const isAtTop = scrollTop === 0 && delta < 0;
        const isAtBottom = scrollTop + clientHeight >= scrollHeight && delta > 0;

        if (isAtTop || isAtBottom) {
            e.preventDefault();
            e.stopPropagation();
        }
    } else {
        e.preventDefault();
        e.stopPropagation();
    }
}

export function preventScrollPropagation(e) {
    e.stopPropagation();
}
