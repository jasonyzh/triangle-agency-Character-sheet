import { S } from './state.js';

export function initDropdowns() {
    const fillSelect = (id, items) => {
        const sel = document.getElementById(id);
        if (!sel) return;
        sel.innerHTML = '<option value="" disabled selected>-- 请选择 --</option>';
        if (items && Array.isArray(items)) {
            items.forEach(item => {
                const val = typeof item === 'string' ? item : item.name;
                const opt = document.createElement('option');
                opt.value = val;
                opt.textContent = val;
                sel.appendChild(opt);
            });
        }
        const customOpt = document.createElement('option');
        customOpt.value = '__CUSTOM__';
        customOpt.textContent = '➤ 自定义 / 手动输入...';
        sel.appendChild(customOpt);
    };
    fillSelect('sel-pAnom', S.CONFIG_DATA.anoms);
    fillSelect('sel-pReal', S.CONFIG_DATA.realities);
    fillSelect('sel-pFunc', S.CONFIG_DATA.functions);
}

export function handlePresetChange(fieldId, value) {
    const wrapper = document.getElementById(`grp-${fieldId}`);
    const input = document.getElementById(fieldId);
    if (value === '__CUSTOM__') {
        wrapper.classList.add('show-input');
        input.value = '';
        input.focus();
    } else {
        input.value = value;
        applyCascadingLogic(fieldId, value);
    }
}

export function resetToDropdown(fieldId) {
    const wrapper = document.getElementById(`grp-${fieldId}`);
    const select = document.getElementById(`sel-${fieldId}`);
    const input = document.getElementById(fieldId);
    wrapper.classList.remove('show-input');
    select.value = '';
    input.value = '';
}

export function applyCascadingLogic(fieldId, value) {
    if (!value) return;

    if (fieldId === 'pReal') {
        const config = S.CONFIG_DATA.realities.find(r => r.name === value);
        if (config) {
            document.getElementById('pTrig1').innerHTML = config.trigger || '';
            document.getElementById('pTrig2').innerHTML = config.overload || '';
        }
    }
    else if (fieldId === 'pFunc') {
        const config = S.CONFIG_DATA.functions.find(f => f.name === value);
        if (config) {
            document.getElementById('pTrig3').innerHTML = config.directive;
            if (config.perms && config.perms.length === 3) {
                document.getElementById('perm1').value = config.perms[0];
                document.getElementById('perm2').value = config.perms[1];
                document.getElementById('perm3').value = config.perms[2];
            }
            const itemListContainer = document.getElementById('list-item');
            const presetItems = (config.items || []).slice().reverse();
            const numToReplace = presetItems.length;
            for (let i = 0; i < numToReplace; i++) {
                if (itemListContainer.firstChild) {
                    itemListContainer.firstChild.remove();
                }
            }
            presetItems.forEach(itemData => {
                window.addItem(itemData, true);
            });

            if (config.Assessment && config.Assessment.length > 0) {
                window.showAssessmentModal(config.Assessment);
            }
        }
    }
    else if (fieldId === 'pAnom') {
        const config = S.CONFIG_DATA.anoms.find(a => a.name === value);
        if (config) {
            const anomListContainer = document.getElementById('list-anom');
            const presetAbilities = (config.abilities || []).slice().reverse();
            const numToReplace = presetAbilities.length;
            for (let i = 0; i < numToReplace; i++) {
                if (anomListContainer.firstChild) {
                    anomListContainer.firstChild.remove();
                }
            }
            presetAbilities.forEach(abilityData => {
                window.addAnom(abilityData, true);
            });
        }
    }
}

export function setHybridInputState(fieldId, value) {
    const select = document.getElementById(`sel-${fieldId}`);
    const wrapper = document.getElementById(`grp-${fieldId}`);
    const input = document.getElementById(fieldId);
    let isPreset = false;
    Array.from(select.options).forEach(opt => { if (opt.value === value) isPreset = true; });
    input.value = value || '';
    if (isPreset) {
        wrapper.classList.remove('show-input');
        select.value = value;
    } else if (value && value.trim() !== '') {
        wrapper.classList.add('show-input');
        select.value = '__CUSTOM__';
    } else {
        wrapper.classList.remove('show-input');
        select.value = '';
    }
}
