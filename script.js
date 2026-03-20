const TPL = {
    login: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>', f: [{id: 'user', l: 'Логин / Email', req: true}, {id: 'pass', l: 'Пароль', t: 'password', req: true, g: true}, {id: 'totp', l: 'Ключ 2FA (TOTP или otpauth://)', g: true}, {id: 'url', l: 'URL', t: 'url'}, {id: 'note', l: 'Заметка', t: 'textarea', r: 2}] },
    totp: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>', f: [{id: 'totp', l: 'Ключ 2FA (TOTP или otpauth://)', g: true, req: true}] },
    card: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>', f: [{id: 'num', l: 'Номер карты', req: true}, {id: 'name', l: 'Имя на карте'}, {id: 'exp', l: 'Срок (ММ/ГГ)'}, {id: 'cvv', l: 'CVV', t: 'password'}, {id: 'pin', l: 'PIN', t: 'password'}, {id: 'note', l: 'Заметка', t: 'textarea', r: 2}] },
    id: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><path d="M12 11h7"/><path d="M12 15h7"/><circle cx="8" cy="11" r="2"/></svg>', f: [{id: 'num', l: 'Номер документа', req: true}, {id: 'name', l: 'ФИО'}, {id: 'issued', l: 'Кем выдан', t: 'textarea', r: 2}, {id: 'date', l: 'Дата выдачи'}, {id: 'note', l: 'Заметка', t: 'textarea', r: 2}] },
    note: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>', f: [{id: 'note', l: 'Текст заметки', t: 'textarea', r: 4}] },
    ssh: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>', f: [{id: 'host', l: 'IP / Host', req: true}, {id: 'user', l: 'Username'}, {id: 'port', l: 'Порт (22)'}, {id: 'priv', l: 'Private Key', t: 'textarea', r: 3}, {id: 'pass', l: 'Passphrase', t: 'password'}, {id: 'note', l: 'Заметка', t: 'textarea', r: 2}] },
    wifi: { i: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>', f: [{id: 'ssid', l: 'Название сети (SSID)', req: true}, {id: 'pass', l: 'Пароль', t: 'password'}, {id: 'note', l: 'Заметка', t: 'textarea', r: 2}] }
};
class SafeKeys {
    constructor() {
        this.vault = []; this.notes = []; this.key = null; this.salt = null;
        this.ent = []; this.entGoal = 800; this.collecting = false;
        this.isNew = false; this.activeTab = 'passwords'; this.fileHandle = null;
        this.pendingImage = null; this.db = null;
        this.privacyMode = localStorage.getItem('safekeys_privacy') === 'true';
        this.passHistoryEnabled = localStorage.getItem('safekeys_history') === 'true';
        this.currentTheme = localStorage.getItem('safekeys_theme') || 'default';
        this.autoLockTime = parseInt(localStorage.getItem('safekeys_locktime') || '10', 10);
        this.autoLockTimer = null;
        this.lastActivity = Date.now();
        this.MAX_BYTES = 499 * 1024 * 1024; // 499 MB
        this.applyTheme(this.currentTheme);
        this.bind(); this.initCanvas(); this.checkCrypto();
        this.initDB();
        this.initActivityTracking();
        this.regSW();
    }
    
    regSW() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('./sw.js').catch(() => {});
        }
    }
    
    initActivityTracking() {
        const h = () => this.handleActivity();
        ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'].forEach(e => document.addEventListener(e, h, {passive: true}));
    }

    handleActivity() {
        if (!this.key) return; // Only track if unlocked
        const now = Date.now();
        if (now - this.lastActivity > 1000) { // Throttle to 1s
            this.lastActivity = now;
            this.resetAutoLock();
        }
    }

    resetAutoLock() {
        clearTimeout(this.autoLockTimer);
        if (!this.key || this.autoLockTime === 0) return;
        this.autoLockTimer = setTimeout(() => {
            if (this.key) {
                this.lock();
                this.toast('Хранилище заблокировано из-за неактивности', 'warn');
            }
        }, this.autoLockTime * 60 * 1000);
    }

    $(id) { return document.getElementById(id); }
    
    applyTheme(theme) {
        const link = this.$('dynamic-theme');
        if (link) {
            if (theme && theme !== 'default') {
                link.href = `styles/${theme}.css`;
            } else {
                link.href = '';
            }
        }
    }

    checkCrypto() { if (!window.isSecureContext || !crypto?.subtle) { this.$('a-create').disabled = true; this.$('a-enter').disabled = true; this.$('err').textContent = 'Шифрование недоступно. Используйте localhost или HTTPS.'; } }

    // === IndexedDB — stores EVERYTHING (vault + fileHandle) ===
    initDB() {
        const req = indexedDB.open('SafeKeysDB', 2);
        req.onupgradeneeded = e => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('sync')) db.createObjectStore('sync', { keyPath: 'id' });
            if (!db.objectStoreNames.contains('vault')) db.createObjectStore('vault', { keyPath: 'id' });
        };
        req.onsuccess = e => {
            this.db = e.target.result;
            this.handleHashLink();
            this.refreshKeyBadge();
            this.restoreFileHandle();
        };
        req.onerror = () => { this.handleHashLink(); this.refreshKeyBadge(); };
    }

    // --- DB helpers ---
    dbPut(store, data) {
        return new Promise((res, rej) => {
            if (!this.db) { rej('no db'); return; }
            const tx = this.db.transaction(store, 'readwrite');
            const r = tx.objectStore(store).put(data);
            r.onsuccess = () => res(); r.onerror = () => rej(r.error);
        });
    }
    dbGet(store, key) {
        return new Promise((res, rej) => {
            if (!this.db) { rej('no db'); return; }
            const tx = this.db.transaction(store, 'readonly');
            const r = tx.objectStore(store).get(key);
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
    }
    dbDel(store, key) {
        return new Promise((res, rej) => {
            if (!this.db) { rej('no db'); return; }
            const tx = this.db.transaction(store, 'readwrite');
            const r = tx.objectStore(store).delete(key);
            r.onsuccess = () => res(); r.onerror = () => rej(r.error);
        });
    }

    // --- Vault in IndexedDB ---
    async saveVaultToDB(raw) {
        try { await this.dbPut('vault', { id: 'main', data: raw }); return true; }
        catch { return false; }
    }
    async loadVaultFromDB() {
        try { const r = await this.dbGet('vault', 'main'); return r?.data || null; }
        catch { return null; }
    }
    async clearVaultFromDB() {
        try { await this.dbDel('vault', 'main'); } catch {}
    }

    // --- FileHandle in IndexedDB ---
    async saveFileHandleToDB(handle) {
        try { await this.dbPut('sync', { id: 'fileHandle', handle }); } catch {}
    }
    async clearFileHandleFromDB() {
        try { await this.dbDel('sync', 'fileHandle'); } catch {}
    }
    async restoreFileHandle() {
        try {
            const r = await this.dbGet('sync', 'fileHandle');
            if (!r?.handle) return;
            const perm = await r.handle.queryPermission({ mode: 'readwrite' });
            if (perm === 'granted') { this.fileHandle = r.handle; this._pendingHandle = null; this.updateSyncUI(); this.toast('Синхронизация восстановлена', 'ok'); }
            else { this._pendingHandle = r.handle; this.updateSyncUI(); }
        } catch {}
    }

    // === Toast ===
    toast(msg, type = '') {
        const t = this.$('toast'); t.textContent = msg;
        t.className = 'toast toast--on' + (type ? ' toast--' + type : '');
        clearTimeout(this._tt); this._tt = setTimeout(() => { t.className = 'toast'; }, 3000);
    }

    // === Sync UI ===
    updateSyncUI() {
        const dot = this.$('sync-dot'), st = this.$('sync-status');
        if (this.fileHandle) { dot.classList.add('sync-dot--on'); st.textContent = 'Синхро: ВКЛ'; }
        else if (this._pendingHandle) { dot.classList.remove('sync-dot--on'); st.textContent = 'Синхро: ожидание'; }
        else { dot.classList.remove('sync-dot--on'); st.textContent = 'Синхронизация'; }
    }
    refreshKeyBadge() {
        // Check if we have vault data in IDB
        this.loadVaultFromDB().then(d => { this.$('v-key').hidden = !d; });
        this.updateSyncUI();
    }
    async handleHashLink() {
        const h = location.hash.substring(1);
        if (h.length > 50) { try { const r = atob(h); JSON.parse(r); await this.saveVaultToDB(r); location.hash = ''; this.toast('Сейф загружен из ссылки', 'ok'); this.refreshKeyBadge(); } catch {} }
    }

    bind() {
        // App-like feel: disable context menu except on inputs
        document.addEventListener('contextmenu', e => {
            if (!e.target.closest('input, textarea')) e.preventDefault();
        });
        this.$('a-create').onclick = () => this.startCreate();
        this.$('a-enter').onclick = () => this.startEnter();
        this.$('a-go').onclick = () => this.submitPass();
        this.$('pw').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); this.submitPass(); } };
        this.$('a-reset').onclick = () => this.resetKey();
        this.$('a-info').onclick = () => this.$('modal-info').classList.add('ov--on');
        this.$('a-info-cx').onclick = () => this.closeModal('modal-info');
        this.$('ent-box').onmousemove = e => this.onEnt(e);
        this.$('ent-box').ontouchmove = e => { const t = e.touches[0], r = this.$('ent-box').getBoundingClientRect(); this.onEnt({ clientX: t.clientX, clientY: t.clientY, offsetX: t.clientX - r.left, offsetY: t.clientY - r.top }); e.preventDefault(); };
        document.querySelectorAll('.tab').forEach(t => { t.onclick = () => this.switchTab(t.dataset.tab); });
        this.$('a-add').onclick = () => this.openAddModal('login', false);
        this.$('a-add-2fa').onclick = () => this.openAddModal('totp', true);
        this.$('a-qr-2fa').onclick = () => this.$('f-qr').click();
        this.$('f-qr').onchange = e => this.onQRPicked(e);
        this.$('a-cx').onclick = () => this.closeModal('modal-add');
        this.$('mf').onsubmit = e => this.saveEntry(e);
        
        // Custom Type Dropdown Logic
        const setupTypeDropdown = (prefix) => {
            const wrap = this.$(prefix + '-type-wrap');
            const valBtn = this.$(prefix + '-type-val');
            const menu = this.$(prefix + '-type-menu');
            const hidden = this.$(prefix + '-type');

            valBtn.onclick = (e) => { e.stopPropagation(); wrap.classList.toggle('dropdown--open'); };
            menu.onclick = (e) => {
                const item = e.target.closest('.dropdown__item');
                if (item) {
                    const val = item.dataset.val;
                    hidden.value = val;
                    valBtn.querySelector('.dropdown__text').textContent = item.textContent.trim();
                    valBtn.querySelector('.dropdown__icon').innerHTML = item.querySelector('svg').outerHTML;
                    wrap.classList.remove('dropdown--open');
                    menu.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
                    this.buildFields(prefix + '-fields', val, prefix + '-');
                }
            };
        };
        setupTypeDropdown('m'); setupTypeDropdown('e');
        
        // Theme Dropdown (in settings)
        const themeWrap = this.$('sett-theme-wrap');
        const themeValBtn = this.$('sett-theme-val');
        const themeMenu = this.$('sett-theme-menu');
        if (themeWrap && themeValBtn && themeMenu) {
            themeValBtn.onclick = (e) => { e.stopPropagation(); themeWrap.classList.toggle('dropdown--open'); };
            themeMenu.onclick = (e) => {
                const item = e.target.closest('.dropdown__item');
                if (item) {
                    const val = item.dataset.val;
                    this.currentTheme = val;
                    localStorage.setItem('safekeys_theme', val);
                    this.applyTheme(val);
                    themeValBtn.querySelector('.dropdown__text').textContent = item.textContent.trim();
                    themeWrap.classList.remove('dropdown--open');
                    themeMenu.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
                }
            };
        }

        // Auto-lock Dropdown (in settings)
        const lockWrap = this.$('sett-lock-wrap');
        const lockValBtn = this.$('sett-lock-val');
        const lockMenu = this.$('sett-lock-menu');
        if (lockWrap && lockValBtn && lockMenu) {
            lockValBtn.onclick = (e) => { e.stopPropagation(); lockWrap.classList.toggle('dropdown--open'); };
            lockMenu.onclick = (e) => {
                const item = e.target.closest('.dropdown__item');
                if (item) {
                    const val = parseInt(item.dataset.val, 10);
                    this.autoLockTime = val;
                    localStorage.setItem('safekeys_locktime', val);
                    this.resetAutoLock();
                    lockValBtn.querySelector('.dropdown__text').textContent = item.textContent.trim();
                    lockWrap.classList.remove('dropdown--open');
                    lockMenu.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
                }
            };
        }
        
        // Custom Dropdown
        this.$('s-val').onclick = (e) => { e.stopPropagation(); this.$('s-wrap').classList.toggle('dropdown--open'); };
        this.$('s-menu').onclick = (e) => {
            const item = e.target.closest('.dropdown__item');
            if (item) {
                const val = item.dataset.val;
                this.$('s').value = val;
                this.$('s-val').textContent = item.textContent;
                this.$('s-wrap').classList.remove('dropdown--open');
                document.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
                this.renderPasswords();
            }
        };
        document.addEventListener('click', () => {
            if(this.$('s-wrap')) this.$('s-wrap').classList.remove('dropdown--open');
            if(this.$('m-type-wrap')) this.$('m-type-wrap').classList.remove('dropdown--open');
            if(this.$('e-type-wrap')) this.$('e-type-wrap').classList.remove('dropdown--open');
            if(this.$('sett-theme-wrap')) this.$('sett-theme-wrap').classList.remove('dropdown--open');
            if(this.$('sett-lock-wrap')) this.$('sett-lock-wrap').classList.remove('dropdown--open');
        });
        this.$('a-add-note').onclick = () => this.openNoteModal();
        this.$('a-ncx').onclick = () => this.closeModal('modal-note');
        this.$('nf').onsubmit = e => this.saveNote(e);
        this.$('qn').oninput = () => this.renderNotes();
        this.$('q2').oninput = () => this.render2FA();
        this.$('p-close').onclick = () => this.closePanel();
        this.$('e-cancel').onclick = () => this.panelShowView();
        this.$('ef').onsubmit = e => this.saveEditEntry(e);
        this.$('a-sync').onclick = () => this.onSyncClick();
        this.$('a-sync-go').onclick = () => this.doSyncSetup();
        this.$('a-sync-cx').onclick = () => this.closeModal('modal-sync');
        this.$('a-exp').onclick = () => this.exportKey();
        this.$('fk').onchange = e => this.importFile(e);
        this.$('a-settings').onclick = () => this.openSettings();
        this.$('a-settings-cx').onclick = () => this.closeSettings();
        this.$('sett-device-bind').onchange = e => this.toggleDeviceBinding(e.target.checked);
        const sPrivacy = this.$('sett-privacy');
        if (sPrivacy) sPrivacy.onchange = e => {
            this.privacyMode = e.target.checked;
            localStorage.setItem('safekeys_privacy', this.privacyMode);
            this.renderPasswords();
            if (this.activeTab === '2fa') this.render2FA();
            if (this.currentItem) this.openDetail(this.currentItem);
            this.toast(this.privacyMode ? 'Режим инкогнито ВКЛ' : 'Режим инкогнито ВЫКЛ', 'ok');
        };

        const sHistory = this.$('sett-pass-history');
        if (sHistory) sHistory.onchange = e => {
            this.passHistoryEnabled = e.target.checked;
            localStorage.setItem('safekeys_history', this.passHistoryEnabled);
        };
        this.$('a-lock').onclick = () => this.lock();
        document.querySelectorAll('.tb-btn[data-cmd]').forEach(b => { b.onclick = () => { document.execCommand(b.dataset.cmd, false, b.dataset.val || null); this.$('n-editor').focus(); }; });
        this.$('a-img').onclick = () => this.$('fi').click();
        this.$('fi').onchange = e => this.onImagePicked(e);
        this.$('a-img-orig').onclick = () => this.insertImage(false);
        this.$('a-img-comp').onclick = () => this.insertImage(true);
        this.$('a-img-cx').onclick = () => this.closeModal('modal-img');
        // Lightbox
        this.$('lb-close').onclick = () => this.closeLightbox();
        this.$('lightbox').onclick = e => { if (e.target === this.$('lightbox')) this.closeLightbox(); };
        this.$('lb-dl').onclick = () => this.downloadLightboxImg();
        // Image click in panel/notes
        document.addEventListener('click', e => {
            if (e.target.tagName === 'IMG' && e.target.closest('.detail-note,.editor')) {
                this.openLightbox(e.target.src); return;
            }
            const btn = e.target.closest('.cp-btn'); if (!btn) return;
            const v = btn.dataset.v; if (!v) return;
            navigator.clipboard.writeText(v).catch(() => { const t = document.createElement('textarea'); t.value = v; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t); });
            const old = btn.innerHTML; btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>'; 
            setTimeout(() => { btn.innerHTML = old; }, 1200);
        });
        document.addEventListener('click', e => {
            const btn = e.target.closest('.a-gen');
            if (btn) { 
                const targetId = btn.dataset.target;
                const inp = this.$(targetId); 
                if (inp) {
                    if (targetId.includes('totp')) inp.value = this.genSecretStr();
                    else inp.value = this.genPassStr();
                }
            }
        });
        this.$('q').oninput = () => this.renderPasswords();
    }
    openSettings() {
        this.$('sett-device-bind').checked = this.deviceBound;
        this.$('sett-privacy').checked = this.privacyMode;
        this.$('sett-pass-history').checked = this.passHistoryEnabled;
        
        // Init theme dropdown state
        const item = this.$('sett-theme-menu').querySelector(`[data-val="${this.currentTheme}"]`);
        if (item) {
            this.$('sett-theme-val').querySelector('.dropdown__text').textContent = item.textContent.trim();
            this.$('sett-theme-menu').querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
        }

        // Init lock dropdown state
        const lockItem = this.$('sett-lock-menu').querySelector(`[data-val="${this.autoLockTime}"]`);
        if (lockItem) {
            this.$('sett-lock-val').querySelector('.dropdown__text').textContent = lockItem.textContent.trim();
            this.$('sett-lock-menu').querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === lockItem));
        }

        this.$('sett-bind-info').hidden = !this.deviceBound;
        if (this.deviceBound) this.$('sett-sync-key').textContent = localStorage.getItem('safekeys_sync');
        this.$('modal-settings').classList.add('ov--on');
    }
    closeSettings() { this.closeModal('modal-settings'); }
    async toggleDeviceBinding(enable) {
        this.$('sett-device-bind').disabled = true;
        await new Promise(r => setTimeout(r, 50));
        try {
            if (enable) {
                const a = new Uint8Array(6); crypto.getRandomValues(a);
                const sk = 'SK-' + Array.from(a).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{4}/g).join('-');
                localStorage.setItem('safekeys_sync', sk);
                this.deviceBound = true;
                this.key = await this.deriveKey(this._currentPass + sk, this.salt);
                this.$('sett-bind-info').hidden = false;
                this.$('sett-sync-key').textContent = sk;
                await this.save();
                this.toast('Привязка включена. Сохраните ключ!', 'warn');
            } else {
                localStorage.removeItem('safekeys_sync');
                this.deviceBound = false;
                this.key = await this.deriveKey(this._currentPass, this.salt);
                this.$('sett-bind-info').hidden = true;
                await this.save();
                this.toast('Привязка к устройству отключена', 'ok');
            }
        } finally { this.$('sett-device-bind').disabled = false; }
    }

    buildFields(containerId, type, prefix, values = {}) {
        const c = this.$(containerId); c.innerHTML = '';
        const tpl = TPL[type] || TPL.login;
        tpl.f.forEach(f => {
            const id = prefix + f.id;
            const val = values[f.id] || '';
            let html = `<label class="fld"><span>${f.l}</span>`;
            if (f.t === 'textarea') {
                html += `<textarea id="${id}" class="inp" rows="${f.r || 3}">${this.h(val)}</textarea>`;
            } else {
                let type = f.t || 'text';
                let cls = 'inp';
                if (type === 'password') {
                    type = 'text';
                    cls += ' inp--mask';
                }
                const inp = `<input type="${type}" id="${id}" class="${cls}" value="${this.h(val)}" ${f.req ? 'required' : ''} autocomplete="new-password">`;
                if (f.g) html += `<div class="fld__row">${inp}<button type="button" class="btn btn--o btn--s a-gen" data-target="${id}">Генерировать</button></div>`;
                else html += inp;
            }
            html += `</label>`;
            c.innerHTML += html;
        });
    }

    // === CUSTOM CONFIRM ===
    ask(msg, title = 'Подтверждение') {
        return new Promise(res => {
            this.$('cf-title').textContent = title;
            this.$('cf-msg').textContent = msg;
            this.$('modal-confirm').classList.add('ov--on');
            const yes = () => { clean(); res(true); };
            const no = () => { clean(); res(false); };
            const clean = () => {
                this.$('cf-yes').onclick = null; this.$('cf-no').onclick = null;
                this.$('modal-confirm').classList.remove('ov--on');
            };
            this.$('cf-yes').onclick = yes;
            this.$('cf-no').onclick = no;
        });
    }

    // === LIGHTBOX ===
    openLightbox(src) {
        this.$('lb-img').src = src;
        // Estimate size
        let info = '';
        if (src.startsWith('data:')) {
            const kb = Math.round(src.length * 0.75 / 1024);
            info = kb > 1024 ? (kb / 1024).toFixed(1) + ' МБ' : kb + ' КБ';
        }
        this.$('lb-info').textContent = info;
        this.$('lightbox').classList.add('lightbox--on');
    }
    closeLightbox() { this.$('lightbox').classList.remove('lightbox--on'); this.$('lb-img').src = ''; }
    downloadLightboxImg() {
        const src = this.$('lb-img').src; if (!src) return;
        const a = document.createElement('a'); a.href = src;
        a.download = 'safekeys_photo_' + Date.now() + '.jpg'; a.click();
    }

    // === SYNC ===
    async onSyncClick() {
        if (this._pendingHandle && !this.fileHandle) {
            try { const p = await this._pendingHandle.requestPermission({ mode: 'readwrite' }); if (p === 'granted') { this.fileHandle = this._pendingHandle; this._pendingHandle = null; this.updateSyncUI(); this.toast('Синхронизация восстановлена', 'ok'); await this.save(); return; } } catch {}
        }
        if (this.fileHandle) {
            const ok = await this.ask('Отключить синхронизацию с файлом?', 'Синхронизация');
            if (ok) { this.fileHandle = null; this._pendingHandle = null; this.clearFileHandleFromDB(); this.updateSyncUI(); this.toast('Синхронизация отключена', 'err'); }
            return;
        }
        if (!window.showSaveFilePicker) { this.toast('Используйте Chrome или Edge', 'err'); return; }
        this.$('modal-sync').classList.add('ov--on');
    }
    async doSyncSetup() {
        this.closeModal('modal-sync');
        try { const h = await window.showSaveFilePicker({ suggestedName: 'safekeys_sync.key', types: [{ description: 'Key', accept: { 'application/octet-stream': ['.key'] } }] }); this.fileHandle = h; this._pendingHandle = null; this.saveFileHandleToDB(h); this.updateSyncUI(); await this.save(); this.toast('Синхронизация включена!', 'ok'); } catch {}
    }

    // === IMAGE ===
    onImagePicked(e) {
        const f = e.target.files[0]; if (!f) return;
        const reader = new FileReader();
        reader.onload = () => { this.pendingImage = reader.result; this.$('img-preview').src = reader.result; this.$('img-info').textContent = `${f.name} — ${Math.round(f.size / 1024)} КБ`; this.$('modal-img').classList.add('ov--on'); };
        reader.readAsDataURL(f); e.target.value = '';
    }
    insertImage(compress) {
        this.closeModal('modal-img'); if (!this.pendingImage) return;
        if (!compress) { this.embedImage(this.pendingImage); return; }
        const img = new Image(); img.onload = () => {
            const max = 800; let w = img.width, h = img.height;
            if (w > max) { h = Math.round(h * max / w); w = max; }
            if (h > max) { w = Math.round(w * max / h); h = max; }
            const c = document.createElement('canvas'); c.width = w; c.height = h;
            c.getContext('2d').drawImage(img, 0, 0, w, h);
            this.embedImage(c.toDataURL('image/jpeg', 0.7));
        }; img.src = this.pendingImage;
    }
    embedImage(src) { const el = document.createElement('img'); el.src = src; this.$('n-editor').appendChild(el); this.$('n-editor').focus(); this.pendingImage = null; }

    async copyPermanentLink() { await this.save(); const r = await this.loadVaultFromDB(); if (!r) return; const u = location.origin + location.pathname + '#' + btoa(r); navigator.clipboard.writeText(u).then(() => this.toast('Ссылка скопирована!', 'ok')); }

    // === TABS/VIEWS ===
    switchTab(t) { 
        this.activeTab = t; 
        document.querySelectorAll('.tab').forEach(b => b.classList.toggle('tab--active', b.dataset.tab === t)); 
        this.$('sec-passwords').hidden = t !== 'passwords'; 
        this.$('sec-2fa').hidden = t !== '2fa';
        this.$('sec-notes').hidden = t !== 'notes'; 
        this.$('sec-audit').hidden = t !== 'audit';
        if (t === 'audit') this.renderAudit();
        if (t === '2fa') this.render2FA(); else clearInterval(this._2faInt);
    }
    showView(n) {
        ['v-menu', 'v-entropy', 'v-pass', 'v-load'].forEach(id => this.$(id).hidden = true);
        if (n) this.$(n).hidden = false;
        this.$('err').textContent = '';
        if (n === 'v-pass') {
            const w = this.$('pw-warn'), q = this.$('pq');
            if (w) w.hidden = !this.isNew;
            if (q) q.hidden = !this.isNew;
            if (this.isNew) {
                this.$('ph').textContent = 'Шаг 1: Задайте секретный вопрос и ответ';
                this.$('pw').placeholder = 'Ваш ответ (Мастер-пароль)';
                if (q) q.value = '';
            } else {
                this.$('ph').textContent = this.question ? 'Вопрос: ' + this.question : 'Введите ответ';
                this.$('pw').placeholder = 'Введите ответ';
            }
        }
    }
    showError(m) { this.$('err').textContent = m; }

    // === AUTH ===
    startCreate() { this.isNew = true; this.ent = []; this.collecting = true; this.showView('v-entropy'); }
    startEnter() {
        this.isNew = false;
        this.loadVaultFromDB().then(raw => {
            if (!raw) { this.$('fk').click(); return; }
            try { 
                const d = JSON.parse(raw); 
                this.question = d.q || ''; 
                this.$('ph').textContent = this.question ? 'Вопрос: ' + this.question : 'Введите мастер-пароль';
            } catch { 
                this.question = ''; 
                this.$('ph').textContent = 'Введите мастер-пароль'; 
            }
            this.showView('v-pass'); this.$('pw').focus();
        });
    }
    async submitPass() {
        const p = this.$('pw').value; if (!p) return; 
        this.$('pw').value = ''; this.showView('v-load');
        // Let the browser paint the loading spinner before freezing the main thread on parsing 400MB JSON
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
        if (this.isNew) {
            this.question = this.$('pq') ? this.$('pq').value.trim() : '';
            this.deviceBound = false;
            try { this.salt = crypto.getRandomValues(new Uint8Array(16)); this.key = await this.deriveKey(p, this.salt); this._currentPass = p; this.vault = []; this.notes = []; await this.save(); this.goToDash(); } catch(e) { console.error(e); this.showView('v-menu'); this.showError('Ошибка'); }
        } else {
            const raw = await this.loadVaultFromDB(); if (!raw) { this.showView('v-menu'); this.showError('Ключ не найден'); return; }
            try {
                const d = JSON.parse(raw); 
                let secretP = p;
                if (d.b) {
                    const sk = localStorage.getItem('safekeys_sync');
                    if (!sk) { this.askSyncKey(raw, p, d); return; }
                    secretP = p + sk;
                }
                this.salt = await this.fromB64(d.s); this.key = await this.deriveKey(secretP, this.salt);
                const dec = await this.decrypt(d.v);
                if (!dec) { this.key = null; this.showView('v-pass'); this.$('ph').textContent = 'Введите мастер-пароль'; this.$('pw').focus(); this.showError('Неверный пароль'); return; }
                this.deviceBound = d.b || false;
                this.vault = dec.vault || []; this.notes = dec.notes || []; this._currentPass = p; this.goToDash(); this.resetAutoLock();
            } catch(e) { console.error(e); this.key = null; this.showView('v-pass'); this.$('ph').textContent = 'Введите мастер-пароль'; this.$('pw').focus(); this.showError('Неверный пароль'); }
        }
    }
    async askSyncKey(raw, p, d) {
        this.$('modal-sync-key').classList.add('ov--on');
        this.$('sync-key-inp').value = '';
        this.$('a-sync-key-go').onclick = async () => {
            const sk = this.$('sync-key-inp').value.trim(); if(!sk) return;
            this.$('modal-sync-key').classList.remove('ov--on'); this.showView('v-load');
            await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
            try {
                this.salt = await this.fromB64(d.s); this.key = await this.deriveKey(p + sk, this.salt);
                const dec = await this.decrypt(d.v);
                if (!dec) throw 0;
                localStorage.setItem('safekeys_sync', sk);
                this.deviceBound = true; this.vault = dec.vault || []; this.notes = dec.notes || []; this._currentPass = p; this.goToDash(); this.resetAutoLock();
            } catch {
                this.showView('v-pass'); this.$('ph').textContent = 'Введите мастер-пароль'; this.$('pw').focus(); this.showError('Неверный ключ синхронизации');
            }
        };
        this.$('a-sync-key-cx').onclick = () => { this.$('modal-sync-key').classList.remove('ov--on'); this.showView('v-pass'); this.$('pw').focus(); };
    }
    async resetKey() { const ok = await this.ask('Удалить сохранённый ключ из этого браузера?', 'Удаление ключа'); if (!ok) return; await this.clearVaultFromDB(); this.refreshKeyBadge(); this.showError('Ключ удалён.'); }

    // === ENTROPY ===
    initCanvas() { this.canvas = this.$('ent-c'); this.ctx = this.canvas.getContext('2d'); const r = () => { const b = this.$('ent-box').getBoundingClientRect(); this.canvas.width = b.width; this.canvas.height = b.height; }; r(); window.addEventListener('resize', r); }
    onEnt(e) {
        if (!this.collecting) return; this.ent.push(e.clientX, e.clientY, performance.now());
        this.ctx.fillStyle = 'rgba(255,255,255,.15)'; this.ctx.beginPath(); this.ctx.arc(e.offsetX, e.offsetY, 1.5, 0, Math.PI * 2); this.ctx.fill();
        const pct = Math.min((this.ent.length / this.entGoal) * 100, 100); this.$('ent-n').textContent = Math.floor(pct) + '%'; this.$('ent-f').style.width = pct + '%';
        if (this.ent.length >= this.entGoal) { this.collecting = false; this.showView('v-pass'); this.$('pq').focus(); }
    }

    // === CRYPTO ===
    // Safe async base64 for huge >400MB vaulted data — yields to main thread to prevent UI freeze!
    async toB64(bytes) {
        let s = '';
        for (let i = 0; i < bytes.length; i += 8192) {
            s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
            if (i % (8192 * 30) === 0) await new Promise(r => setTimeout(r, 0));
        }
        return btoa(s);
    }
    async fromB64(str) {
        const bin = atob(str); const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i);
            if (i % 250000 === 0) await new Promise(r => setTimeout(r, 0));
        }
        return bytes;
    }

    async deriveKey(pw, s) { const r = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits', 'deriveKey']); return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: s, iterations: 100000, hash: 'SHA-256' }, r, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }
    async encrypt(d) { const iv = crypto.getRandomValues(new Uint8Array(12)); const e = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, new TextEncoder().encode(JSON.stringify(d))); return { c: await this.toB64(new Uint8Array(e)), i: await this.toB64(iv) }; }
    async decrypt(o) { try { const iv = await this.fromB64(o.i); const ct = await this.fromB64(o.c); return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, ct))); } catch { return null; } }

    // === SAVE — .key file is primary, IndexedDB is cache ===
    async save() {
        // Yield to allow UI like toasts or loaders to render before heavy sync tasks
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
        const e = await this.encrypt({ vault: this.vault, notes: this.notes });
        const raw = JSON.stringify({ s: await this.toB64(this.salt), v: e, q: this.question || '', b: this.deviceBound });

        // Check 499 MB limit
        const sz = new Blob([raw]).size;
        if (sz > this.MAX_BYTES) {
            this.toast('Превышен лимит 499 МБ! Удалите данные.', 'err');
            return false;
        }

        // Cache in IndexedDB
        await this.saveVaultToDB(raw);
        this.updateStorageBar(sz);

        // Sync to .key file (PRIMARY storage)
        if (this.fileHandle) {
            try { const w = await this.fileHandle.createWritable(); await w.write(raw); await w.close(); }
            catch { this.fileHandle = null; this.clearFileHandleFromDB(); this.updateSyncUI(); this.toast('Синхронизация потеряна', 'err'); }
        }
        return true;
    }

    // === STORAGE INDICATOR ===
    updateStorageBar(bytes) {
        if (!bytes) bytes = 0;
        const mb = bytes / (1024 * 1024);
        const pct = Math.min((bytes / this.MAX_BYTES) * 100, 100);
        this.$('st-text').textContent = `Хранилище: ${mb.toFixed(2)} / 499 МБ`;
        this.$('st-detail').textContent = `Паролей: ${this.vault.length} \u00b7 Заметок: ${this.notes.length}`;
        const fill = this.$('st-fill');
        fill.style.width = pct + '%';
        fill.className = 'storage-fill' + (pct > 90 ? ' storage-fill--danger' : pct > 70 ? ' storage-fill--warn' : '');
    }
    async exportKey() { await this.save(); const r = await this.loadVaultFromDB(); if (!r) return; const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([r], { type: 'application/octet-stream' })); a.download = 'safekeys_' + new Date().toISOString().slice(0, 10) + '.key'; a.click(); this.toast('Ключ экспортирован', 'ok'); }
    async importFile(e) {
        const f = e.target.files[0]; if (!f) return;
        try { const t = await f.text(); const p = JSON.parse(t); if (!p.s || !p.v) throw 0; await this.saveVaultToDB(t); this.refreshKeyBadge(); this.isNew = false; this.showView('v-pass'); this.$('ph').textContent = 'Введите мастер-пароль'; this.$('pw').focus(); this.toast('Ключ импортирован', 'ok'); } catch { this.showError('Неверный формат'); }
    }
    goToDash() {
        if (this.$('app-header')) this.$('app-header').classList.add('app-header--hidden');
        this.$('pg-auth').classList.remove('page--active'); this.$('pg-dash').classList.add('page--active'); this.renderPasswords(); this.renderNotes(); if(this.activeTab==='audit')this.renderAudit(); this.recalcStorage(); 
    }
    async recalcStorage() { const r = await this.loadVaultFromDB(); if (r) this.updateStorageBar(new Blob([r]).size); }
    lock() {
        if (this.$('app-header')) this.$('app-header').classList.remove('app-header--hidden');
        clearTimeout(this.autoLockTimer); this.key = null; this._currentPass = null; this.vault = []; this.notes = []; this.salt = null; this.closePanel(); this.$('pg-dash').classList.remove('page--active'); this.$('pg-auth').classList.add('page--active'); this.showView('v-menu'); this.refreshKeyBadge(); 
    }

    // === AUDIT ===
    renderAudit() {
        let weak = 0, old = 0;
        const counts = {};
        this.vault.forEach(p => { if(p.pass) counts[p.pass] = (counts[p.pass] || 0) + 1; });
        
        let reuse = Object.values(counts).filter(c => c > 1).length;
        this.$('as-reuse').textContent = reuse;
        this.$('as-reuse').parentElement.className = 'audit-stat ' + (reuse > 0 ? 'audit-stat--danger' : '');
        
        const now = Date.now(), oldThresh = 180 * 24 * 60 * 60 * 1000;
        const issues = [];
        
        this.vault.forEach(p => {
            if (!p.pass) return; // Only audit objects with passwords
            const isOld = now - p.ts > oldThresh;
            const isReuse = counts[p.pass] > 1;
            const isWeak = p.pass.length < 8 || !/[A-Z]/.test(p.pass) || !/[0-9]/.test(p.pass);
            
            if (isWeak) weak++;
            if (isOld) old++;
            
            let lvl = 'warn', m = [];
            if (isWeak) { m.push('Слабый пароль'); lvl = 'danger'; }
            if (isReuse) { m.push(`Используется еще ${counts[p.pass] - 1} раз(а)`); lvl = 'danger'; }
            if (isOld) m.push('Старше 6 месяцев');
            
            if (m.length > 0) issues.push({ p, msg: m.join(', '), lvl });
        });
        
        this.$('as-weak').textContent = weak;
        this.$('as-weak').parentElement.className = 'audit-stat ' + (weak > 0 ? 'audit-stat--danger' : '');
        this.$('as-old').textContent = old;
        this.$('as-old').parentElement.className = 'audit-stat ' + (old > 0 ? 'audit-stat--warn' : '');
        
        const list = this.$('audit-list'); list.innerHTML = '';
        issues.sort((a,b) => a.lvl === 'danger' ? -1 : 1).forEach(i => {
            const d = document.createElement('div');
            d.className = 'audit-item audit-item--' + i.lvl;
            d.innerHTML = `<div class="audit-item__l"><span class="audit-item__title">${this.h(i.p.title)}</span><span class="audit-item__desc">${i.msg}</span></div><button class="btn btn--o btn--s">Изменить</button>`;
            d.querySelector('button').onclick = () => { this.switchTab('passwords'); this.openDetail(i.p); };
            list.appendChild(d);
        });
        this.$('empty-audit').hidden = issues.length > 0;
    }

    // === PASSWORDS ===
    getIconHtml(title, urlStr, type = 'login') {
        const tpl = TPL[type] || TPL.login;
        if (type !== 'login' && tpl.i) return `<div class="card__icon">${tpl.i}</div>`;
        if (!urlStr) return `<div class="card__icon">${this.h(title.charAt(0).toUpperCase())}</div>`;
        try {
            let u = urlStr.startsWith('http') ? urlStr : 'https://' + urlStr;
            const h = new URL(u).hostname;
            return `<div class="card__icon card__icon--img"><img src="https://icons.duckduckgo.com/ip3/${h}.ico" alt="" onerror="this.parentElement.className='card__icon'; this.parentElement.innerHTML='${this.h(title.charAt(0).toUpperCase())}'"></div>`;
        } catch { return `<div class="card__icon">${this.h(title.charAt(0).toUpperCase())}</div>`; }
    }
    renderTagFilters() {
        const tSet = new Set();
        this.vault.forEach(v => { if (v.tags) v.tags.forEach(t => tSet.add(t)); });
        const tf = this.$('tag-filters'); tf.innerHTML = '';
        if (tSet.size === 0) return;
        ['Все', ...Array.from(tSet).sort()].forEach(t => {
            const btn = document.createElement('button');
            const isActive = (t === 'Все' && !this.activeTag) || (t === this.activeTag);
            btn.className = 'tag-chip' + (isActive ? ' tag-chip--active' : '');
            btn.textContent = t;
            btn.onclick = () => { this.activeTag = t === 'Все' ? null : t; this.renderPasswords(); };
            tf.appendChild(btn);
        });
    }
    renderPasswords() {
        this.renderTagFilters();
        const q = this.$('q').value.toLowerCase(), s = this.$('s').value;
        let l = this.vault.filter(x => {
            const tr = x.title.toLowerCase().includes(q);
            const ir = ['user', 'num', 'host', 'note'].some(k => x[k] && x[k].toLowerCase().includes(q));
            return tr || ir;
        });
        if (this.activeTag) l = l.filter(x => x.tags && x.tags.includes(this.activeTag));
        if (s === 'new') l.sort((a, b) => b.ts - a.ts); else if (s === 'old') l.sort((a, b) => a.ts - b.ts); else l.sort((a, b) => a.title.localeCompare(b.title));
        const g = this.$('grid'); g.innerHTML = ''; this.$('empty').hidden = l.length > 0;
        l.forEach(i => {
            const c = document.createElement('div'); c.className = 'card'; c.onclick = () => this.openDetail(i);
            const type = i.type || 'login';
            const icon = this.getIconHtml(i.title, i.url, type);
            const tHtml = i.tags && i.tags.length ? `<div class="card__tags">${i.tags.map(t => `<span class="tag">${this.h(t)}</span>`).join('')}</div>` : '';
            let prev = i.user || i.num || i.ssid || i.host || 'Запись';
            if (type === 'note') prev = i.note ? i.note.substring(0, 100) : 'Заметка';
            const maskCls = (this.privacyMode && type !== 'note') ? ' text--mask' : '';
            c.innerHTML = `<div class="card__top"><div class="card__title-wrap">${icon}<span class="card__name">${this.h(i.title)}</span></div><span class="card__date">${new Date(i.ts).toLocaleDateString('ru-RU')}</span></div><div class="card__preview${maskCls}">${this.h(prev)}</div>${i.url ? `<div class="card__url">${this.h(i.url)}</div>` : ''}${tHtml}`;
            g.appendChild(c);
        });
    }
    openAddModal(type = 'login', lock = false) { 
        this.$('mf').reset(); this.$('m-id').value = ''; this.$('m-tags').value = ''; 
        this.$('m-type').value = type; 
        const item = this.$('m-type-menu').querySelector(`[data-val="${type}"]`);
        this.$('m-type-val').querySelector('.dropdown__text').textContent = item.textContent.trim();
        this.$('m-type-val').querySelector('.dropdown__icon').innerHTML = item.querySelector('svg').outerHTML;
        this.$('m-type-menu').querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
        this.buildFields('m-fields', type, 'm-');
        const tw = this.$('m-type-wrap'); if (tw) tw.closest('.fld').style.display = lock ? 'none' : 'block';
        this.$('modal-add').classList.add('ov--on'); 
    }
    closeModal(id) { this.$(id).classList.remove('ov--on'); }
    async saveEntry(e) { 
        e.preventDefault(); 
        const id = this.$('m-id').value; 
        const tags = this.$('m-tags').value.split(',').map(t => t.trim()).filter(t => t); 
        const type = this.$('m-type').value;
        const en = { id: id || Date.now().toString(), type, title: this.$('m-name').value, tags, ts: Date.now() }; 
        TPL[type].f.forEach(f => {
            const el = this.$('m-' + f.id);
            if (el) en[f.id] = el.value;
        });
        if (id) { const i = this.vault.findIndex(x => x.id === id); if (i >= 0) this.vault[i] = en; } else this.vault.push(en); 
        await this.save(); this.closeModal('modal-add'); this.renderPasswords(); if (this.activeTab === '2fa') this.render2FA(); if (this.activeTab === 'notes') this.renderNotes(); this.toast('Запись сохранена', 'ok'); 
    }
    async delEntry(id) { const ok = await this.ask('Удалить эту запись безвозвратно?', 'Удаление'); if (!ok) return; this.vault = this.vault.filter(x => x.id !== id); await this.save(); this.closePanel(); this.renderPasswords(); if (this.activeTab === '2fa') this.render2FA(); if (this.activeTab === 'notes') this.renderNotes(); this.toast('Запись удалена', 'ok'); }

    // === DETAIL ===
    openDetail(i) {
        this.currentItem = i; this.$('p-title').textContent = i.title; this.$('p-view').hidden = false; this.$('p-edit').hidden = true;
        const type = i.type || 'login';
        const tpl = TPL[type] || TPL.login;
        let h = '';
        if (i.totp) h += `<div id="totp-container"></div>`;
        tpl.f.forEach(f => {
            if (i[f.id] && f.id !== 'totp') {
                if (f.t === 'textarea') h += `<div class="detail-row"><div class="detail-label">${f.l}</div><div class="detail-note">${this.h(i[f.id])}</div></div>`;
                else h += this.dr(f.l, i[f.id], true, f.t === 'password');
            }
        });
        if (i.tags && i.tags.length) h += `<div class="detail-row"><div class="detail-label">Категории</div><div style="color:var(--c8);font-size:.88rem">${i.tags.map(t => `<span class="tag">${this.h(t)}</span>`).join(' ')}</div></div>`;
        h += `<div class="detail-row"><div class="detail-label">Изменено</div><div style="color:var(--c7);font-size:.82rem">${new Date(i.ts).toLocaleString('ru-RU')}</div></div>`;
        
        // History
        if (i.history && i.history.length > 0) {
            h += `<div class="detail-row"><div class="detail-label">История паролей</div>`;
            h += `<div style="display:flex;flex-direction:column;gap:8px;margin-top:8px;">`;
            i.history.forEach((hist) => {
                const dt = new Date(hist.d).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
                h += `<div style="display:flex;justify-content:space-between;align-items:center;background:rgba(255,255,255,0.02);padding:8px 12px;border-radius:var(--rs);gap:10px;">`;
                h += `<span style="flex:1;font-family:var(--m);font-size:0.85rem;word-break:break-all;" class="${this.privacyMode ? 'text--mask' : ''}">${this.privacyMode ? '••••••••' : this.h(hist.pass)}</span>`;
                h += `<span style="font-size:0.7rem;color:var(--c6);">${dt}</span>`;
                h += `<button class="cp-btn" data-v="${this.h(hist.pass)}" title="Копировать старый пароль"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>`;
                h += `</div>`;
            });
            h += `</div></div>`;
        }

        h += `<div class="panel__actions"><button class="btn btn--o btn--s" onclick="app.panelEdit()">Изменить</button><button class="btn btn--o btn--s btn--danger" onclick="app.delEntry('${i.id}')">Удалить</button></div>`;
        this.$('p-view').innerHTML = h; this.$('panel').classList.add('panel--open');
        if (i.totp) this.startTOTPInterval(this.parseTOTPSecret(i.totp));
    }
    dr(l, v, cp = false, mask = false) { 
        const isMask = mask || this.privacyMode;
        const d = isMask ? '••••••••' : this.h(v); 
        return cp ? `<div class="detail-row"><div class="detail-label">${l}</div><div class="detail-value detail-value--cp"><span class="${isMask ? 'text--mask' : ''}">${d}</span><button class="cp-btn" data-v="${this.h(v)}" title="Скопировать"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button></div></div>` 
                  : `<div class="detail-row"><div class="detail-label">${l}</div><div style="color:var(--c8);font-size:.88rem;padding:4px 0" class="${isMask ? 'text--mask' : ''}">${d}</div></div>`; 
    }
    panelEdit() { 
        const i = this.currentItem; 
        this.$('p-title').textContent = 'Редактирование'; 
        this.$('p-view').hidden = true; 
        this.$('p-edit').hidden = false; 
        this.$('e-id').value = i.id; 
        this.$('e-name').value = i.title; 
        const type = i.type || 'login';
        this.$('e-type').value = type;
        const item = this.$('e-type-menu').querySelector(`[data-val="${type}"]`);
        this.$('e-type-val').querySelector('.dropdown__text').textContent = item.textContent.trim();
        this.$('e-type-val').querySelector('.dropdown__icon').innerHTML = item.querySelector('svg').outerHTML;
        this.$('e-type-menu').querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
        this.buildFields('e-fields', type, 'e-', i);
        const tw = this.$('e-type-wrap'); if (tw) tw.closest('.fld').style.display = type === 'totp' ? 'none' : 'block';
        this.$('e-tags').value = i.tags ? i.tags.join(', ') : ''; 
    }
    panelShowView() { if (this.currentItem) this.openDetail(this.currentItem); }
    async saveEditEntry(e) { 
        e.preventDefault(); 
        const id = this.$('e-id').value; 
        const tags = this.$('e-tags').value.split(',').map(t => t.trim()).filter(t => t); 
        const type = this.$('e-type').value;
        
        const oldEntry = this.vault.find(x => x.id === id);
        const newEntry = { id, type, title: this.$('e-name').value, tags, ts: Date.now() }; 
        
        TPL[type].f.forEach(f => {
            const el = this.$('e-' + f.id);
            if (el) newEntry[f.id] = el.value;
        });

        // Password history tracking
        if (this.passHistoryEnabled && oldEntry && newEntry.pass && oldEntry.pass !== newEntry.pass) {
            newEntry.history = oldEntry.history ? [...oldEntry.history] : [];
            newEntry.history.unshift({ pass: oldEntry.pass, d: oldEntry.ts }); // Store old password with its timestamp
            if (newEntry.history.length > 5) { // Keep only the last 5 passwords
                newEntry.history.pop();
            }
        } else if (oldEntry && oldEntry.history) {
            newEntry.history = oldEntry.history; // Carry over existing history if password didn't change or history is disabled
        }

        const i = this.vault.findIndex(x => x.id === id); 
        if (i >= 0) this.vault[i] = newEntry; 
        
        this.currentItem = newEntry; await this.save(); this.renderPasswords(); if (this.activeTab === '2fa') this.render2FA(); if (this.activeTab === 'notes') this.renderNotes(); this.openDetail(newEntry); this.toast('Изменения сохранены', 'ok'); 
    }

    base32ToBuf(base32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = 0, value = 0, index = 0;
        const cleanStr = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
        const output = new Uint8Array((cleanStr.length * 5 / 8) | 0);
        for (let i = 0; i < cleanStr.length; i++) {
            value = (value << 5) | alphabet.indexOf(cleanStr[i]);
            bits += 5;
            if (bits >= 8) {
                output[index++] = (value >>> (bits - 8)) & 255;
                bits -= 8;
            }
        }
        return output.buffer;
    }
    parseTOTPSecret(str) {
        if (!str) return '';
        str = str.trim();
        if (str.startsWith('otpauth://')) {
            try { return new URL(str).searchParams.get('secret') || ''; } catch { return ''; }
        }
        return str.replace(/\s+/g, '');
    }
    
    // === QR SCANNING ===
    onQRPicked(e) {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (re) => {
            const img = new Image();
            img.onload = () => {
                const cvs = document.createElement('canvas');
                cvs.width = img.width; cvs.height = img.height;
                const ctx = cvs.getContext('2d');
                ctx.drawImage(img, 0, 0);
                const data = ctx.getImageData(0, 0, cvs.width, cvs.height);
                const code = jsQR(data.data, data.width, data.height);
                if (code) {
                    this.handleScannedQR(code.data);
                } else {
                    this.toast('QR код не найден на изображении', 'err');
                }
                e.target.value = '';
            };
            img.src = re.target.result;
        };
        reader.readAsDataURL(file);
    }
    handleScannedQR(uri) {
        let name = 'Сканированный ключ';
        let secret = uri;
        
        if (uri.startsWith('otpauth://')) {
            try {
                const url = new URL(uri);
                const s = url.searchParams.get('secret');
                if (s) {
                    secret = uri;
                    let n = decodeURIComponent(url.pathname.split(':').pop() || '').split('/').pop();
                    const issuer = url.searchParams.get('issuer');
                    if (issuer) n = issuer + (n ? ' (' + n + ')' : '');
                    if (n) name = n;
                }
            } catch (e) {}
        }
        
        this.openAddModal('totp', true);
        this.$('m-name').value = name;
        const tEl = this.$('m-totp');
        if (tEl) tEl.value = secret;
        this.toast('QR код считан, введите название', 'ok');
    }
    async generateTOTP(secretBase32) {
        if (!secretBase32) return null;
        try {
            const keyBytes = this.base32ToBuf(secretBase32);
            if(keyBytes.byteLength === 0) return null;
            const t = Math.floor(Date.now() / 1000 / 30);
            const timeBuf = new ArrayBuffer(8);
            new DataView(timeBuf).setUint32(4, t);
            const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
            const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, timeBuf));
            const offset = hmac[hmac.length - 1] & 0x0f;
            const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
            let str = (code % 1000000).toString();
            while (str.length < 6) str = '0' + str;
            return str;
        } catch (e) { return null; }
    }
    async updateTOTPUI(secret) {
        const c = this.$('totp-container');
        if (!c) return;
        const code = await this.generateTOTP(secret);
        if (!code) {
           c.innerHTML = '<div class="detail-label">2FA Код</div><div style="color:var(--red);font-size:0.88rem;margin-bottom:24px">Неверный ключ 2FA</div>';
           return;
        }
        const epoch = Math.floor(Date.now() / 1000);
        const remain = 30 - (epoch % 30);
        const pct = (remain / 30) * 100;
        let color = 'var(--cw)';
        if (remain <= 5) color = 'var(--red)';
        
        c.innerHTML = `
            <div class="totp-box">
                <div class="totp-l">
                    <div class="totp-code${this.privacyMode ? ' text--mask' : ''}" style="color:${color}">${code.substring(0,3)} ${code.substring(3)}</div>
                    <div class="totp-label">Нажмите чтобы скопировать</div>
                </div>
                <div class="totp-r">
                    <div class="totp-timer">
                        <svg viewBox="0 0 36 36"><path class="totp-timer-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" /><path class="totp-timer-fill" style="stroke:${color}" stroke-dasharray="${pct}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" /></svg>
                        <div class="totp-timer-text" style="color:${color}">${remain}</div>
                    </div>
                </div>
            </div>
        `;
        const box = c.querySelector('.totp-box');
        if (box) box.onclick = () => {
            navigator.clipboard.writeText(code).catch(() => { const t = document.createElement('textarea'); t.value = code; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t); });
            this.toast('2FA код скопирован!', 'ok');
        };
    }
    startTOTPInterval(secret) {
        clearInterval(this._totpInt);
        if (!secret) return;
        this.updateTOTPUI(secret);
        this._totpInt = setInterval(() => this.updateTOTPUI(secret), 1000);
    }
    
    // === 2FA SECTION ===
    async render2FA() {
        const q = this.$('q2').value.toLowerCase();
        const l = this.vault.filter(x => x.totp && (x.title.toLowerCase().includes(q) || (x.user || '').toLowerCase().includes(q)));
        const g = this.$('totp-grid'); g.innerHTML = ''; this.$('empty-2fa').hidden = l.length > 0;
        
        l.forEach(i => {
            const c = document.createElement('div');
            c.className = 'card card--2fa';
            c.dataset.id = i.id;
            c.onclick = () => { this.openDetail(i); };
            
            const icon = this.getIconHtml(i.title, i.url, i.type || 'login');
            c.innerHTML = `
                ${icon}
                <span class="card__name">${this.h(i.title)}</span>
                <div class="totp-code" id="t-code-${i.id}">000 000</div>
                <div class="totp-timer" id="t-timer-${i.id}">
                    <svg viewBox="0 0 36 36"><path class="totp-timer-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" /><path class="totp-timer-fill" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" /></svg>
                    <div class="totp-timer-text">0</div>
                </div>
            `;
            g.appendChild(c);
        });
        
        clearInterval(this._2faInt);
        const updateAll = async () => {
            for(const i of l) {
                const secret = this.parseTOTPSecret(i.totp);
                const code = await this.generateTOTP(secret);
                const epoch = Math.floor(Date.now() / 1000);
                const remain = 30 - (epoch % 30);
                const pct = (remain / 30) * 100;
                let color = 'var(--cw)'; if (remain <= 5) color = 'var(--red)';
                
                const cEl = this.$('t-code-' + i.id);
                const tEl = this.$('t-timer-' + i.id);
                if (cEl && tEl) {
                    cEl.textContent = code ? `${code.substring(0,3)} ${code.substring(3)}` : 'ERROR';
                    cEl.style.color = color;
                    const fill = tEl.querySelector('.totp-timer-fill');
                    const text = tEl.querySelector('.totp-timer-text');
                    fill.setAttribute('stroke-dasharray', `${pct}, 100`);
                    fill.style.stroke = color;
                    text.textContent = remain;
                    text.style.color = color;
                }
            }
        };
        updateAll();
        this._2faInt = setInterval(updateAll, 1000);
    }

    closePanel() { clearInterval(this._totpInt); this.$('panel').classList.remove('panel--open'); this.currentItem = null; }

    // === NOTES ===
    renderNotes() {
        const q = this.$('qn').value.toLowerCase();
        let l = this.notes.filter(x => x.title.toLowerCase().includes(q) || (x.plain || '').toLowerCase().includes(q));
        l.sort((a, b) => b.ts - a.ts);
        const g = this.$('notes-grid'); g.innerHTML = ''; this.$('empty-notes').hidden = l.length > 0;
        l.forEach(i => {
            const c = document.createElement('div'); c.className = 'card card--note'; c.onclick = () => this.openNoteDetail(i);
            const tmp = document.createElement('div'); tmp.innerHTML = i.html || i.text || '';
            const firstImg = tmp.querySelector('img');
            const plain = tmp.textContent.substring(0, 120);
            c.innerHTML = `<div class="card__top"><span class="card__name">${this.h(i.title)}</span><span class="card__date">${new Date(i.ts).toLocaleDateString('ru-RU')}</span></div><div class="card__excerpt">${this.h(plain)}</div>${firstImg ? `<img class="card__thumb" src="${firstImg.src}" alt="">` : ''}`;
            g.appendChild(c);
        });
    }
    openNoteModal(item = null) {
        this.$('mn-title').textContent = item ? 'Редактировать' : 'Новая заметка';
        this.$('n-id').value = item?.id || ''; this.$('n-name').value = item?.title || '';
        this.$('n-editor').innerHTML = item?.html || item?.text || '';
        this.$('modal-note').classList.add('ov--on');
    }
    async saveNote(e) {
        e.preventDefault(); const id = this.$('n-id').value;
        const html = this.$('n-editor').innerHTML;
        const tmp = document.createElement('div'); tmp.innerHTML = html;
        const note = { id: id || Date.now().toString(), title: this.$('n-name').value, html, plain: tmp.textContent, ts: Date.now() };
        if (id) { const i = this.notes.findIndex(x => x.id === id); if (i >= 0) this.notes[i] = note; } else this.notes.push(note);
        await this.save(); this.closeModal('modal-note'); this.renderNotes(); this.toast('Заметка сохранена', 'ok');
    }
    openNoteDetail(i) {
        this.currentItem = i;
        this.$('p-title').textContent = i.title; this.$('p-view').hidden = false; this.$('p-edit').hidden = true;
        // Count images
        const tmp = document.createElement('div'); tmp.innerHTML = i.html || '';
        const imgs = tmp.querySelectorAll('img');
        const imgCount = imgs.length;
        let imgSize = 0;
        imgs.forEach(img => { if (img.src.startsWith('data:')) imgSize += Math.round(img.src.length * 0.75); });
        const imgSizeMB = (imgSize / (1024 * 1024)).toFixed(1);
        const date = new Date(i.ts).toLocaleString('ru-RU');

        let h = `<div class="detail-note">${i.html || this.h(i.text || '')}</div>`;
        h += `<div class="detail-meta">`;
        h += `<span class="detail-meta__item">Изменено: ${date}</span>`;
        if (imgCount) h += `<span class="detail-meta__item">Фото: ${imgCount} (${imgSizeMB} МБ)</span>`;
        h += `</div>`;
        h += `<div class="panel__actions"><button class="btn btn--o btn--s" onclick="app.openNoteModal(app.notes.find(n=>n.id==='${i.id}'));app.closePanel()">Изменить</button><button class="btn btn--o btn--s btn--danger" onclick="app.delNote('${i.id}')">Удалить</button></div>`;
        this.$('p-view').innerHTML = h;
        this.$('panel').classList.add('panel--open');
    }
    async delNote(id) { const ok = await this.ask('Удалить эту заметку безвозвратно?', 'Удаление'); if (!ok) return; this.notes = this.notes.filter(x => x.id !== id); await this.save(); this.closePanel(); this.renderNotes(); this.toast('Заметка удалена', 'ok'); }

    h(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
    genPassStr() { const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_+-='; return Array.from(crypto.getRandomValues(new Uint8Array(24)), b => c[b % c.length]).join(''); }
    genSecretStr() { const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; return Array.from(crypto.getRandomValues(new Uint8Array(16)), b => c[b % c.length]).join(''); }
}
let app; document.addEventListener('DOMContentLoaded', () => { app = new SafeKeys(); });
