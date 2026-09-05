import { S, ATTRS } from './state.js';
import { getAuthHeaders } from './auth.js';
import { showToast, escapeHtmlText, preventWheelPenetration } from './ui.js';
import { renderDots } from './track.js';

export function showAssessmentModal(assessmentData) {
    if (S.isReadOnly) return;

    S.currentAssessmentData = assessmentData;
    const modal = document.getElementById('assessment-modal');
    const body = document.getElementById('assessmentBody');

    body.innerHTML = '';

    body.innerHTML = assessmentData.map((qa, index) => {
        const qNum = index + 1;
        return `
            <div class="assessment-question">
                <div class="assessment-q-text">${qNum}. ${escapeHtmlText(qa.q)}</div>
                <div class="assessment-options">
                    <label class="assessment-option" onclick="selectAssessmentOption(${index}, 1)">
                        <input type="radio" name="q${index}" value="a1">
                        <span class="assessment-option-text">${escapeHtmlText(qa.a1[0])}</span>
                        <span class="assessment-option-badge">${escapeHtmlText(qa.a1[1])} +${qa.a1[2]}</span>
                    </label>
                    <label class="assessment-option" onclick="selectAssessmentOption(${index}, 2)">
                        <input type="radio" name="q${index}" value="a2">
                        <span class="assessment-option-text">${escapeHtmlText(qa.a2[0])}</span>
                        <span class="assessment-option-badge">${escapeHtmlText(qa.a2[1])} +${qa.a2[2]}</span>
                    </label>
                </div>
            </div>
        `;
    }).join('');

    body.scrollTop = 0;
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    modal.removeEventListener('wheel', preventWheelPenetration);
    modal.addEventListener('wheel', preventWheelPenetration, { passive: false });
}

export function selectAssessmentOption(qIndex, optNum) {
    const radio = document.querySelector(`input[name="q${qIndex}"][value="a${optNum}"]`);
    if (radio) radio.checked = true;

    const options = document.querySelectorAll(`.assessment-question:nth-child(${qIndex + 1}) .assessment-option`);
    options.forEach((opt, i) => {
        if (i === optNum - 1) opt.classList.add('selected');
        else opt.classList.remove('selected');
    });
}

export function submitAssessment() {
    if (!S.currentAssessmentData) return;

    const totalQuestions = S.currentAssessmentData.length;
    const answeredCount = document.querySelectorAll('.assessment-question input[type="radio"]:checked').length;

    if (answeredCount < totalQuestions) {
        showToast('请回答所有问题后再提交', 'error');
        return;
    }

    ATTRS.forEach(attrName => {
        const inputEl = document.querySelector(`.attr-input[data-attr="${attrName}"]`);
        if (inputEl) {
            inputEl.value = 0;
            renderDots(attrName, 0);
        }
    });

    const attrModifications = {};

    S.currentAssessmentData.forEach((qa, index) => {
        const selected = document.querySelector(`input[name="q${index}"]:checked`);
        if (selected) {
            const answerKey = selected.value;
            const answerData = qa[answerKey];
            const attrName = answerData[1];
            const attrValue = parseInt(answerData[2]) || 0;

            if (!attrModifications[attrName]) attrModifications[attrName] = 0;
            attrModifications[attrName] += attrValue;
        }
    });

    for (const attrName in attrModifications) {
        const inputEl = document.querySelector(`.attr-input[data-attr="${attrName}"]`);
        if (inputEl) {
            const newValue = attrModifications[attrName];
            inputEl.value = newValue;
            renderDots(attrName, newValue);
        }
    }

    S.lastAssessmentAttributes = Object.keys(attrModifications);

    closeAssessmentModal();
    window.triggerAutoSave();

    const attrSummary = Object.entries(attrModifications)
        .map(([name, val]) => `${name} +${val}`)
        .join(', ');
    showToast(`评估完成！${attrSummary}`, 'success');
}

export function closeAssessmentModal() {
    const modal = document.getElementById('assessment-modal');
    modal.classList.remove('active');
    S.currentAssessmentData = null;
    document.body.style.overflow = '';
    modal.removeEventListener('wheel', preventWheelPenetration);
}

export async function confirmU2Unleash() {
    if (!S.charId || !S.token) return;
    const watchCount = parseInt(document.getElementById('watchCount').value) || 0;
    if (watchCount < 3) { showToast('申诫不足3点', 'error'); return; }

    const overlay = document.getElementById('u2-overlay');
    const eyeIcon = document.getElementById('u2-eye-icon');
    eyeIcon.classList.remove('eye-open', 'eye-closing');
    overlay.classList.add('active');
    setTimeout(() => { eyeIcon.classList.add('eye-open'); }, 200);
}

export function cancelU2Unleash() { closeU2Overlay(); }

export async function executeU2Unleash() {
    const eyeIcon = document.getElementById('u2-eye-icon');
    eyeIcon.classList.remove('eye-open');
    eyeIcon.classList.add('eye-closing');
    setTimeout(() => { document.getElementById('u2-overlay').classList.remove('active'); }, 400);

    try {
        const res = await fetch(`/api/character/${S.charId}/u2-unleash`, { method: 'POST', headers: getAuthHeaders() });
        const data = await res.json();
        if (data.success) { document.getElementById('watchCount').value = data.watchCount; showToast('已消耗3点申诫', 'success'); }
        else { showToast(data.message || '操作失败', 'error'); }
    } catch (e) { showToast('操作失败', 'error'); }
}

export function closeU2Overlay() {
    const eyeIcon = document.getElementById('u2-eye-icon');
    eyeIcon.classList.remove('eye-open');
    eyeIcon.classList.add('eye-closing');
    setTimeout(() => { document.getElementById('u2-overlay').classList.remove('active'); }, 300);
}
