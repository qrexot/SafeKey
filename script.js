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
        // Отключаем Supabase - работаем только на localStorage
        this.SB_URL = window.SAFEKEYS_SUPABASE_URL || 'https://exjgabrncmicwqfbncop.supabase.co';
        this.SB_KEY = window.SAFEKEYS_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4amdhYnJuY21pY3dxZmJuY29wIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYwOTY2NjUsImV4cCI6MjA5MTY3MjY2NX0.aPlaWN1D5BCFkR04G1cVDSitd4b05lkKaH95wZd2fYo';
        this.supabase = this.createSupabaseClient();
        console.log('Working in Supabase-only mode');

        this.vault = []; this.notes = []; this.key = null; this.salt = null;
        this.macKey = null;
        this.ent = []; this.entGoal = 800; this.collecting = false;
        this.activeTab = 'passwords'; this.anonymousKey = null;
        this.accessPasswordHash = null;
        // media upload removed
        this.privacyMode = false;
        this.passHistoryEnabled = false;
        this.guardMaxAttempts = 5;
        this.guardAction = 'lock';
        this.guardLockMinutes = 60;
        this.guardFailedAttempts = 0;
        this.guardLockedUntil = 0;
        this.guardServerEnabled = false;
        this.currentTheme = 'default';
        this.autoLockTime = 10;
        this.syncKey = '';
        this.autoLockTimer = null;
        this.lastActivity = Date.now();
        this.MAX_BYTES = 100 * 1024 * 1024; // 100 MB for cloud
        this.applyTheme(this.currentTheme);
        this.bind(); this.initCanvas(); this.checkCrypto();
        this.initActivityTracking();
        this.regSW();
        this.regManifest();
        this.initSupabaseListener();
        this._rpcMissing = false;
        this._hasMacColumn = true;
    }

    isRpcMissingError(err) {
        if (!err) return false;
        const msg = `${err.message || ''} ${err.details || ''} ${err.hint || ''}`.toLowerCase();
        return err.code === 'PGRST202' || err.status === 404 || msg.includes('could not find the function') || msg.includes('schema cache');
    }

    isMissingColumnError(err, columnName, tableName) {
        if (!err) return false;
        const msg = `${err.message || ''} ${err.details || ''}`.toLowerCase();
        const col = (columnName || '').toLowerCase();
        const tbl = (tableName || '').toLowerCase();
        return msg.includes("could not find the") && msg.includes(`'${col}'`) && msg.includes(`'${tbl}'`) && msg.includes('schema cache');
    }

    async withMacFallback(fn) {
        try {
            return await fn();
        } catch (e) {
            if (this._hasMacColumn && this.isMissingColumnError(e, 'mac', 'vaults')) {
                this._hasMacColumn = false;
                console.warn("Column 'mac' missing on 'vaults'; retrying without MAC storage");
                return await fn();
            }
            throw e;
        }
    }

    async rpcOrTable({ rpc, params, tableOp }) {
        if (!this.ensureSupabase()) throw new Error('Supabase not configured');
        if (!this._rpcMissing) {
            const { data, error } = await this.supabase.rpc(rpc, params);
            if (!error) return { data, via: 'rpc' };
            if (!this.isRpcMissingError(error)) throw error;
            this._rpcMissing = true;
            console.warn(`RPC ${rpc} missing; falling back to table access`);
        }
        const { data, error } = await tableOp();
        if (error) throw error;
        return { data, via: 'table' };
    }

    async getVaultRow(pwHash, anonymousKey = null) {
        const key = anonymousKey || this.anonymousKey;
        return await this.withMacFallback(async () => {
            const selectCols = this._hasMacColumn
                ? 'anonymous_key,salt,encrypted_data,question,mac'
                : 'anonymous_key,salt,encrypted_data,question';
            const { data } = await this.rpcOrTable({
                rpc: 'safekeys_get_vault',
                params: { p_anonymous_key: key, p_password_hash: pwHash },
                tableOp: () => this.supabase
                    .from('vaults')
                    .select(selectCols)
                    .eq('anonymous_key', key)
                    .eq('password_hash', pwHash)
                    .limit(1)
            });
            const row = Array.isArray(data) ? data[0] : null;
            return row || null;
        });
    }

    guardStorageKey(anonymousKey = null) {
        return 'safekeys_guard_' + (anonymousKey || this.anonymousKey || 'global');
    }

    loadGuardSettings(anonymousKey = null) {
        try {
            const raw = localStorage.getItem(this.guardStorageKey(anonymousKey));
            if (!raw) return;
            const cfg = JSON.parse(raw);
            this.guardMaxAttempts = Number(cfg.maxAttempts) || 5;
            this.guardAction = cfg.action === 'wipe' ? 'wipe' : 'lock';
            this.guardLockMinutes = Number(cfg.lockMinutes) || 60;
            this.guardFailedAttempts = Number(cfg.failedAttempts) || 0;
            this.guardLockedUntil = Number(cfg.lockedUntil) || 0;
        } catch {}
    }

    saveGuardSettings() {
        try {
            localStorage.setItem(this.guardStorageKey(), JSON.stringify({
                maxAttempts: this.guardMaxAttempts,
                action: this.guardAction,
                lockMinutes: this.guardLockMinutes,
                failedAttempts: this.guardFailedAttempts,
                lockedUntil: this.guardLockedUntil
            }));
        } catch {}
    }

    getGuardRemainingMs() {
        return Math.max(0, (this.guardLockedUntil || 0) - Date.now());
    }

    formatDuration(ms) {
        const min = Math.ceil(ms / 60000);
        if (min <= 1) return 'меньше минуты';
        if (min < 60) return `${min} мин.`;
        const hours = Math.ceil(min / 60);
        return `${hours} ч.`;
    }

    async saveGuardSettingsToServer() {
        if (!this.anonymousKey || !this.accessPasswordHash || !this.ensureSupabase()) return false;
        const { error } = await this.supabase.rpc('safekeys_update_security', {
            p_anonymous_key: this.anonymousKey,
            p_password_hash: this.accessPasswordHash,
            p_guard_max_attempts: this.guardMaxAttempts,
            p_guard_action: this.guardAction,
            p_guard_lock_minutes: this.guardLockMinutes
        });
        if (error) {
            this.guardServerEnabled = false;
            return false;
        }
        this.guardServerEnabled = true;
        return true;
    }

    async authAttemptWithGuard(anonymousKey, passwordHash) {
        if (this.ensureSupabase()) {
            const { data, error } = await this.supabase.rpc('safekeys_auth_attempt', {
                p_anonymous_key: anonymousKey,
                p_password_hash: passwordHash
            });
            if (!error) {
                this.guardServerEnabled = true;
                const row = Array.isArray(data) ? data[0] : null;
                if (!row) return { ok: false, reason: 'reject' };
                if (row.status === 'ok') {
                    return {
                        ok: true,
                        row: {
                            anonymous_key: row.anonymous_key,
                            salt: row.salt,
                        encrypted_data: row.encrypted_data,
                        question: row.question,
                            mac: row.mac,
                            guard_max_attempts: row.guard_max_attempts,
                            guard_action: row.guard_action,
                            guard_lock_minutes: row.guard_lock_minutes
                        }
                    };
                }
                return {
                    ok: false,
                    reason: row.status || 'reject',
                    failedAttempts: Number(row.failed_attempts) || 0,
                    lockedUntil: row.locked_until ? new Date(row.locked_until).getTime() : 0,
                    remainingAttempts: Number(row.remaining_attempts) || 0
                };
            }
            if (!this.isRpcMissingError(error)) throw error;
            this.guardServerEnabled = false;
        }

        this.loadGuardSettings(anonymousKey);
        const remainingMs = this.getGuardRemainingMs();
        if (remainingMs > 0) return { ok: false, reason: 'locked', lockedUntil: this.guardLockedUntil };

        const row = await this.getVaultRow(passwordHash, anonymousKey);
        if (row) {
            this.guardFailedAttempts = 0;
            this.guardLockedUntil = 0;
            this.anonymousKey = anonymousKey;
            this.saveGuardSettings();
            return { ok: true, row };
        }

        this.guardFailedAttempts += 1;
        if (this.guardFailedAttempts >= this.guardMaxAttempts) {
            if (this.guardAction === 'wipe') {
                localStorage.setItem('safekeys_anon_key', anonymousKey);
                localStorage.removeItem(this.guardStorageKey(anonymousKey));
                return { ok: false, reason: 'deleted' };
            }
            this.guardLockedUntil = Date.now() + this.guardLockMinutes * 60000;
        }
        this.anonymousKey = anonymousKey;
        this.saveGuardSettings();
        return {
            ok: false,
            reason: this.guardLockedUntil > Date.now() ? 'locked' : 'reject',
            lockedUntil: this.guardLockedUntil,
            failedAttempts: this.guardFailedAttempts,
            remainingAttempts: Math.max(0, this.guardMaxAttempts - this.guardFailedAttempts)
        };
    }

    async triggerLocalGuardFailure() {
        this.loadGuardSettings();
        this.guardFailedAttempts += 1;
        if (this.guardFailedAttempts >= this.guardMaxAttempts) {
            if (this.guardAction === 'wipe') {
                await this.wipeAccountFromDB();
                return { reason: 'wiped' };
            }
            this.guardLockedUntil = Date.now() + this.guardLockMinutes * 60000;
        }
        this.saveGuardSettings();
        return {
            reason: this.guardLockedUntil > Date.now() ? 'locked' : 'reject',
            lockedUntil: this.guardLockedUntil,
            remainingAttempts: Math.max(0, this.guardMaxAttempts - this.guardFailedAttempts)
        };
    }

    resetLocalGuardFailures() {
        this.loadGuardSettings();
        this.guardFailedAttempts = 0;
        this.guardLockedUntil = 0;
        this.saveGuardSettings();
    }

    createSupabaseClient() {
        const isConfigured = this.SB_URL && this.SB_KEY && !this.SB_URL.includes('YOUR-PROJECT') && !this.SB_KEY.includes('YOUR_SUPABASE');
        if (!isConfigured || !window.supabase?.createClient) return null;
        return window.supabase.createClient(this.SB_URL, this.SB_KEY);
    }

    ensureSupabase() {
        if (this.supabase) return true;
        this.showView('v-menu');
        this.showError('Сервер не настроен: проверьте параметры подключения.');
        return false;
    }
    
    regSW() {
        const canUseServiceWorker = location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
        if (canUseServiceWorker && 'serviceWorker' in navigator) {
            navigator.serviceWorker.register('./sw.js').catch(() => {});
        }
    }

    regManifest() {
        if (location.protocol === 'file:') return;
        const manifest = document.createElement('link');
        manifest.rel = 'manifest';
        manifest.href = 'manifest.json';
        document.head.appendChild(manifest);
    }

    async initSupabaseListener() {
        const vAccount = this.$('v-account');
        const vMaster = this.$('v-master');
        if (vAccount) vAccount.hidden = false;
        if (vMaster) vMaster.hidden = true;
        const savedKey = localStorage.getItem('safekeys_anon_key');
        const keyInput = this.$('auth-key');
        const intro = vAccount ? vAccount.querySelector('p') : null;
        if (savedKey && keyInput) {
            keyInput.value = savedKey;
            keyInput.hidden = true;
            if (intro) intro.textContent = 'Введите пароль, ключ уже сохранен на этом устройстве';
            const switchBtn = document.createElement('button');
            switchBtn.type = 'button';
            switchBtn.className = 'link';
            switchBtn.textContent = 'Войти с другим ключом';
            switchBtn.style.margin = '0 0 12px';
            switchBtn.onclick = () => {
                localStorage.removeItem('safekeys_anon_key');
                keyInput.value = '';
                keyInput.hidden = false;
                switchBtn.remove();
                if (intro) intro.textContent = 'Введите ключ и пароль. На этом устройстве ключ понадобится только один раз';
                keyInput.focus();
            };
            keyInput.insertAdjacentElement('afterend', switchBtn);
        }
        if (!this.supabase) this.ensureSupabase();
        return;
        // Р аботаем только с localStorage
        const legacySavedKey = null;
        if (legacySavedKey) {
            this.anonymousKey = legacySavedKey;
            const vAccount = this.$('v-account');
            const vMaster = this.$('v-master');
            if (vAccount) vAccount.hidden = true;
            if (vMaster) vMaster.hidden = false;
            this.checkExistingVault();
        } else {
            const vAccount = this.$('v-account');
            const vMaster = this.$('v-master');
            if (vAccount) vAccount.hidden = false;
            if (vMaster) vMaster.hidden = true;
        }
    }

    handleAuthChange(anonymousKey) {
        this.anonymousKey = anonymousKey;
        if (this.anonymousKey) {
            this.$('v-account').hidden = true;
            this.$('v-master').hidden = false;
            this.checkExistingVault();
        } else {
            this.lock();
            this.$('v-account').hidden = false;
            this.$('v-master').hidden = true;
        }
    }

    async checkExistingVault() {
        if (!this.anonymousKey) return;
        if (!this.ensureSupabase()) return;
        if (!this.accessPasswordHash) {
            this.showView('v-menu');
            return;
        }
        this.showView('v-load');
        try {
            const row = await this.getVaultRow(this.accessPasswordHash);
            if (!row) {
                this.showAccountDeletedNotice();
                return;
            }
            
            if (row && row.salt && row.encrypted_data) {
                this.isNew = false;
                this.question = row.question || '';
                const ph = this.$('ph');
                const pq = this.$('pq');
                if (ph) ph.textContent = this.question ? 'Вопрос: ' + this.question : 'Введите мастер-пароль';
                if (pq) pq.hidden = true;
            } else {
                this.isNew = true;
                const ph = this.$('ph');
                const pq = this.$('pq');
                const pwWarn = this.$('pw-warn');
                if (ph) ph.textContent = 'Шаг 1: задайте секретный вопрос и ответ';
                if (pq) pq.hidden = false;
                if (pwWarn) pwWarn.hidden = false;
            }
            this.showView('v-master');
        } catch (err) {
            console.error('Check vault error:', err);
            this.showView('v-menu');
            this.showError('Не удалось загрузить аккаунт с сервера: ' + (err.message || err.details || 'ошибка запроса'));
        }
        return;
        try {
            // Загружаем из localStorage
            const localData = null;
            let data = null;
            
            if (localData) {
                data = JSON.parse(localData);
                console.log('Loaded from disabled storage:', data);
            }
            
            if (data && data.salt && data.encrypted_data) {
                // Существующий сейф с данными
                this.isNew = false;
                this.question = data.question || '';
                const ph = this.$('ph');
                const pq = this.$('pq');
                if (ph) ph.textContent = this.question ? 'Вопрос: ' + this.question : 'Введите мастер-пароль';
                if (pq) pq.hidden = true;
            } else {
                // Новый сейф - нужно настроить мастер-пароль
                this.isNew = true;
                const ph = this.$('ph');
                const pq = this.$('pq');
                const pwWarn = this.$('pw-warn');
                if (ph) ph.textContent = 'Шаг 1: Задайте секретный вопрос и ответ';
                if (pq) pq.hidden = false;
                if (pwWarn) pwWarn.hidden = false;
            }
            this.showView('v-master');
        } catch (err) {
            console.error('Check vault error:', err);
            this.showView('v-master');
            // Assume new vault on error
            this.isNew = true;
            const ph = this.$('ph');
            const pq = this.$('pq');
            if (ph) ph.textContent = 'Шаг 1: Задайте секретный вопрос и ответ';
            if (pq) pq.hidden = false;
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

    checkCrypto() { 
        if (!window.isSecureContext || !crypto?.subtle) { 
            const loginBtn = this.$('a-login-key');
            const createBtn = this.$('a-create-key');
            if (loginBtn) loginBtn.disabled = true;
            if (createBtn) createBtn.disabled = true;
            if(this.$('err')) this.$('err').textContent = 'Шифрование недоступно. Используйте localhost или HTTPS.'; 
        } 
    }

    // === Toast & Error ===
    toast(msg, type = '') {
        const t = this.$('toast');
        if (!t) return;
        t.textContent = msg;
        t.className = 'toast toast--on' + (type ? ' toast--' + type : '');
        setTimeout(() => t.classList.remove('toast--on'), 3000);
    }
    
    showError(msg, options = {}) {
        const err = this.$('err');
        if (err) {
            err.textContent = msg;
            err.style.display = 'block';
            setTimeout(() => { err.style.display = 'none'; }, 5000);
        }
        if (options.toast !== false) this.toast(msg, 'err');
    }

    showAccountDeletedNotice() {
        const message = 'Аккаунт удалён на сервере. Сохранённый ключ остался на этом устройстве, но открыть данные по нему больше нельзя.';
        this.showView('v-menu');
        this.showError(message, { toast: false });
    }

    setLoadingStatus(title = 'Связь с облаком...', detail = 'Проверяем защищённое хранилище') {
        const titleEl = this.$('load-title');
        const detailEl = this.$('load-detail');
        if (titleEl) titleEl.textContent = title;
        if (detailEl) detailEl.textContent = detail;
    }

    setBusy(elOrId, busy) {
        const el = typeof elOrId === 'string' ? this.$(elOrId) : elOrId;
        if (!el) return;
        el.classList.toggle('is-busy', !!busy);
        el.disabled = !!busy;
    }
    
    showView(id) {
        const topViews = ['v-menu', 'v-entropy', 'v-load', 'v-key'];
        const showInsideMenu = id === 'v-account' || id === 'v-master';
        topViews.forEach(v => {
            const el = this.$(v);
            if (el) el.hidden = showInsideMenu ? v !== 'v-menu' : v !== id;
        });

        const account = this.$('v-account');
        const master = this.$('v-master');
        if (account) account.hidden = id === 'v-master';
        if (master) master.hidden = id !== 'v-master';
    }
    
    closeModal(id) {
        const modal = this.$(id);
        if (modal) modal.classList.remove('ov--on');
    }

    bind() {
        document.addEventListener('contextmenu', e => {
            if (!e.target.closest('input, textarea')) e.preventDefault();
        });

        // Anonymous Key Auth Buttons - с проверкой существования
        const createBtn = this.$('a-create-key');
        const loginBtn = this.$('a-login-key');
        const showRegBtn = this.$('show-register');
        const showLogBtn = this.$('show-login');
        
        if (createBtn) createBtn.onclick = () => this.authCreateKey();
        if (loginBtn) loginBtn.onclick = () => this.authLoginWithKey();
        
        // Toggle between login and register
        if (showRegBtn) showRegBtn.onclick = () => {
            const loginSec = this.$('login-section');
            const regSec = this.$('register-section');
            if (loginSec) loginSec.style.display = 'none';
            if (regSec) regSec.style.display = 'block';
        };
        if (showLogBtn) showLogBtn.onclick = () => {
            const loginSec = this.$('login-section');
            const regSec = this.$('register-section');
            if (loginSec) loginSec.style.display = 'block';
            if (regSec) regSec.style.display = 'none';
        };
        
        const goBtn = this.$('a-go');
        const pwInput = this.$('pw');
        if (goBtn) goBtn.onclick = () => this.submitPass();
        if (pwInput) pwInput.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); this.submitPass(); } };
        
        const infoBtn = this.$('a-info');
        const infoCxBtn = this.$('a-info-cx');
        if (infoBtn) infoBtn.onclick = () => {
            const modal = this.$('modal-info');
            if (modal) modal.classList.add('ov--on');
        };
        if (infoCxBtn) infoCxBtn.onclick = () => this.closeModal('modal-info');
        
        const entBox = this.$('ent-box');
        if (entBox) {
            entBox.onmousemove = e => this.onEnt(e);
            entBox.ontouchmove = e => { 
                const t = e.touches[0], r = entBox.getBoundingClientRect(); 
                this.onEnt({ clientX: t.clientX, clientY: t.clientY, offsetX: t.clientX - r.left, offsetY: t.clientY - r.top }); 
                e.preventDefault(); 
            };
        }
        
        const tabs = document.querySelector('.tabs');
        if (tabs) {
            tabs.onclick = e => {
                const tab = e.target.closest('.tab');
                if (tab) this.switchTab(tab.dataset.tab);
            };
        }
        
        const addBtn = this.$('a-add');
        const add2faBtn = this.$('a-add-2fa');
        const cxBtn = this.$('a-cx');
        const mfForm = this.$('mf');
        
        if (addBtn) addBtn.onclick = () => this.openAddModal('login', false);
        if (add2faBtn) add2faBtn.onclick = () => this.openAddModal('totp', true);
        if (cxBtn) cxBtn.onclick = () => this.closeModal('modal-add');
        if (mfForm) mfForm.onsubmit = e => this.saveEntry(e);

        const grid = this.$('grid');
        if (grid) {
            grid.addEventListener('click', (e) => {
                const card = e.target.closest('.card');
                if (!card) return;
                const id = card.dataset.id;
                if (!id) return;
                const item = this.vault.find(x => x.id === id);
                if (item) this.openDetail(item);
            }, true);
        }
        
        const setupTypeDropdown = (prefix) => {
            const wrap = this.$(prefix + '-type-wrap');
            const valBtn = this.$(prefix + '-type-val');
            const menu = this.$(prefix + '-type-menu');
            const hidden = this.$(prefix + '-type');
            if(!valBtn) return;
            valBtn.onclick = (e) => { e.stopPropagation(); wrap.classList.toggle('dropdown--open'); };
            if (menu) menu.onclick = (e) => {
                const item = e.target.closest('.dropdown__item');
                if (item) {
                    const val = item.dataset.val;
                    hidden.value = val;
                    const textEl = valBtn.querySelector('.dropdown__text');
                    const iconEl = valBtn.querySelector('.dropdown__icon');
                    const itemSvg = item.querySelector('svg');
                    if (textEl) textEl.textContent = item.textContent.trim();
                    if (iconEl && itemSvg) iconEl.innerHTML = itemSvg.outerHTML;
                    wrap.classList.remove('dropdown--open');
                    menu.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
                    this.buildFields(prefix + '-fields', val, prefix + '-');
                }
            };
        };
        setupTypeDropdown('m'); 
        setupTypeDropdown('e');
        
        // Lock dropdown
        const lockBtn = this.$('sett-lock-val');
        const lockMenu = this.$('sett-lock-menu');
        const lockWrap = this.$('sett-lock-wrap');
        if (lockBtn) lockBtn.onclick = (e) => { e.stopPropagation(); if (lockWrap) lockWrap.classList.toggle('dropdown--open'); };
        if (lockMenu) lockMenu.onclick = (e) => {
            const item = e.target.closest('.dropdown__item');
            if (item) {
                this.autoLockTime = parseInt(item.dataset.val, 10);
                this.resetAutoLock();
            }
        };

        const setupGuardDropdown = (key) => {
            const wrap = this.$(`sett-guard-${key}-wrap`);
            const btn = this.$(`sett-guard-${key}-val`);
            const menu = this.$(`sett-guard-${key}-menu`);
            const input = this.$(`sett-guard-${key}`);
            if (!wrap || !btn || !menu || !input) return;
            btn.onclick = (e) => {
                e.stopPropagation();
                ['sett-guard-max-wrap', 'sett-guard-action-wrap', 'sett-guard-lock-wrap'].forEach(id => {
                    if (id !== wrap.id) this.$(id)?.classList.remove('dropdown--open');
                });
                wrap.classList.toggle('dropdown--open');
            };
            menu.onclick = (e) => {
                const item = e.target.closest('.dropdown__item');
                if (!item) return;
                input.value = item.dataset.val;
                btn.querySelector('.dropdown__text').textContent = item.textContent.trim();
                menu.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
                wrap.classList.remove('dropdown--open');
                this.updateGuardSettingsFromUI(true);
            };
        };
        ['max', 'action', 'lock'].forEach(setupGuardDropdown);

        const sVal = this.$('s-val');
        const sMenu = this.$('s-menu');
        const sWrap = this.$('s-wrap');
        const sInput = this.$('s');
        if (sVal) sVal.onclick = (e) => { e.stopPropagation(); if (sWrap) sWrap.classList.toggle('dropdown--open'); };
        if (sMenu) sMenu.onclick = (e) => {
            const item = e.target.closest('.dropdown__item');
            if (item && sInput && sVal) {
                sInput.value = item.dataset.val;
                sVal.textContent = item.textContent;
                this.renderPasswords();
            }
        };

        document.addEventListener('click', () => {
            ['s-wrap', 'm-type-wrap', 'e-type-wrap', 'sett-lock-wrap', 'sett-guard-max-wrap', 'sett-guard-action-wrap', 'sett-guard-lock-wrap'].forEach(id => {
                const el = this.$(id); 
                if(el) el.classList.remove('dropdown--open');
            });
        });

        const addNoteBtn = this.$('a-add-note');
        const ncxBtn = this.$('a-ncx');
        const nfForm = this.$('nf');
        const qnInput = this.$('qn');
        const q2Input = this.$('q2');
        
        if (addNoteBtn) addNoteBtn.onclick = () => this.openNoteModal();
        if (ncxBtn) ncxBtn.onclick = () => this.closeModal('modal-note');
        if (nfForm) nfForm.onsubmit = e => this.saveNote(e);
        if (qnInput) qnInput.oninput = () => this.renderNotes();
        if (q2Input) q2Input.oninput = () => this.render2FA();

        const notesGrid = this.$('notes-grid');
        if (notesGrid) {
            notesGrid.addEventListener('click', (e) => {
                const card = e.target.closest('.card');
                if (!card) return;
                const id = card.dataset.id;
                if (!id) return;
                const item = this.notes.find(x => x.id === id);
                if (item) this.openNoteDetail(item);
            }, true);
        }
        
        const pClose = this.$('p-close');
        const eCancel = this.$('e-cancel');
        const efForm = this.$('ef');
        const settingsBtn = this.$('a-settings');
        const settingsCxBtn = this.$('a-settings-cx');
        const deviceBind = this.$('sett-device-bind');
        
        if (pClose) pClose.onclick = () => this.closePanel();
        if (eCancel) eCancel.onclick = () => this.panelShowView();
        if (efForm) efForm.onsubmit = e => this.saveEditEntry(e);
        if (settingsBtn) settingsBtn.onclick = () => this.openSettings();
        if (settingsCxBtn) settingsCxBtn.onclick = () => this.closeSettings();
        if (deviceBind) deviceBind.onchange = e => this.toggleDeviceBinding(e.target.checked);
        
        const sPrivacy = this.$('sett-privacy');
        if (sPrivacy) sPrivacy.onchange = e => {
            this.privacyMode = e.target.checked;
            this.renderPasswords();
            if (this.activeTab === '2fa') this.render2FA();
        };

        const sHistory = this.$('sett-pass-history');
        if (sHistory) sHistory.onchange = e => {
            this.passHistoryEnabled = e.target.checked;
        };

        const lockOutBtn = this.$('a-lock');
        if (lockOutBtn) lockOutBtn.onclick = () => this.authSignOut();
        const exportBtn = this.$('a-exp');
        if (exportBtn) exportBtn.onclick = () => this.exportKey();
        
        document.querySelectorAll('.tb-btn[data-cmd]').forEach(b => { 
            b.onclick = () => { 
                document.execCommand(b.dataset.cmd, false, b.dataset.val || null); 
                const editor = this.$('n-editor');
                if (editor) editor.focus(); 
            }; 
        });
        
        document.addEventListener('click', e => {
            const btn = e.target.closest('.cp-btn'); 
            if (!btn) return;
            const v = btn.dataset.v; 
            if (!v) return;
            navigator.clipboard.writeText(v).catch(() => { 
                const t = document.createElement('textarea'); 
                t.value = v; 
                document.body.appendChild(t); 
                t.select(); 
                document.execCommand('copy'); 
                document.body.removeChild(t); 
            });
            const old = btn.innerHTML; 
            btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>'; 
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
        
        const qInput = this.$('q');
        if (qInput) qInput.oninput = () => this.renderPasswords();
        
        const fkInput = this.$('fk');
        if (fkInput) fkInput.onchange = e => this.importFile(e);
    }
    openSettings() {
        this.loadGuardSettings();
        this.$('sett-device-bind').checked = this.deviceBound;
        this.$('sett-privacy').checked = this.privacyMode;
        this.$('sett-pass-history').checked = this.passHistoryEnabled;
        const guardMax = this.$('sett-guard-max');
        const guardAction = this.$('sett-guard-action');
        const guardLock = this.$('sett-guard-lock');
        if (guardMax) guardMax.value = String(this.guardMaxAttempts);
        if (guardAction) guardAction.value = this.guardAction;
        if (guardLock) guardLock.value = String(this.guardLockMinutes);
        this.setGuardDropdownValue('max', this.guardMaxAttempts);
        this.setGuardDropdownValue('action', this.guardAction);
        this.setGuardDropdownValue('lock', this.guardLockMinutes);
        this.updateGuardStatus();
        
        // Init lock dropdown state
        const lockItem = this.$('sett-lock-menu').querySelector(`[data-val="${this.autoLockTime}"]`);
        if (lockItem) {
            this.$('sett-lock-val').querySelector('.dropdown__text').textContent = lockItem.textContent.trim();
            this.$('sett-lock-menu').querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === lockItem));
        }

        this.$('sett-bind-info').hidden = !this.deviceBound;
        if (this.deviceBound) this.$('sett-sync-key').textContent = this.syncKey;
        this.$('modal-settings').classList.add('ov--on');
    }
    closeSettings() { this.closeModal('modal-settings'); }

    setGuardDropdownValue(key, value) {
        const input = this.$(`sett-guard-${key}`);
        const btn = this.$(`sett-guard-${key}-val`);
        const menu = this.$(`sett-guard-${key}-menu`);
        const item = menu?.querySelector(`[data-val="${value}"]`);
        if (input) input.value = String(value);
        if (btn && item) btn.querySelector('.dropdown__text').textContent = item.textContent.trim();
        if (menu && item) menu.querySelectorAll('.dropdown__item').forEach(i => i.classList.toggle('dropdown__item--active', i === item));
    }

    updateGuardStatus() {
        const el = this.$('sett-guard-status');
        if (!el) return;
        const remainingMs = this.getGuardRemainingMs();
        el.classList.remove('guard-status--ok', 'guard-status--danger');
        if (this.guardAction === 'wipe') {
            el.textContent = `После ${this.guardMaxAttempts} неверных попыток сейф будет удалён. Используйте только если у вас есть бэкап.`;
            el.classList.add('guard-status--danger');
        } else if (remainingMs > 0) {
            el.textContent = `Аккаунт заморожен ещё на ${this.formatDuration(remainingMs)}.`;
            el.classList.add('guard-status--danger');
        } else {
            el.textContent = this.guardServerEnabled
                ? 'Серверная защита активна: попытки входа считаются на сервере.'
                : 'Локальная защита активна. После настройки сервера попытки будут считаться и там.';
            el.classList.add('guard-status--ok');
        }
    }

    async updateGuardSettingsFromUI(syncServer = false) {
        const maxEl = this.$('sett-guard-max');
        const actionEl = this.$('sett-guard-action');
        const lockEl = this.$('sett-guard-lock');
        this.guardMaxAttempts = Math.max(1, Number(maxEl?.value) || 5);
        this.guardAction = actionEl?.value === 'wipe' ? 'wipe' : 'lock';
        this.guardLockMinutes = Math.max(1, Number(lockEl?.value) || 60);
        this.saveGuardSettings();
        let serverOk = false;
        if (syncServer) serverOk = await this.saveGuardSettingsToServer();
        this.updateGuardStatus();
        this.toast(serverOk ? 'Защита от перебора сохранена на сервере' : 'Защита от перебора сохранена локально', serverOk ? 'ok' : 'warn');
    }

    async toggleDeviceBinding(enable) {
        this.$('sett-device-bind').disabled = true;
        await new Promise(r => setTimeout(r, 50));
        try {
            if (enable) {
                const a = new Uint8Array(6); crypto.getRandomValues(a);
                const sk = 'SK-' + Array.from(a).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{4}/g).join('-');
                this.syncKey = sk;
                this.deviceBound = true;
                this.key = await this.deriveKey(this._currentPass + sk, this.salt);
                this.$('sett-bind-info').hidden = false;
                this.$('sett-sync-key').textContent = sk;
                await this.save();
                this.toast('Привязка включена. Сохраните ключ!', 'warn');
            } else {
                this.syncKey = '';
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
        const fields = type === 'login' ? tpl.f.filter(f => f.id !== 'totp').map(f => f.id === 'note' ? {...f, r: 1} : f) : tpl.f;
        fields.forEach(f => {
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

    // === ANONYMOUS KEY AUTH ===
    generateAnonymousKey() {
        // Генерация уникального ключа формата: SK-XXXX-XXXX-XXXX-XXXX-XXXX
        const array = new Uint8Array(20);
        crypto.getRandomValues(array);
        const hex = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        return 'SK-' + hex.match(/.{4}/g).join('-');
    }

    async hashPassword(password) {
        // Хешируем пароль для хранения на сервере
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async authCreateKey() {
        if (!this.ensureSupabase()) return;
        console.log('=== authCreateKey START ===');
        this.setBusy('a-create-key', true);
        const password = this.$('register-password').value.trim();
        const passwordConfirm = this.$('register-password-confirm').value.trim();
        
        if (!password || password.length < 6) {
            this.setBusy('a-create-key', false);
            this.toast('Пароль должен быть минимум 6 символов', 'err');
            return;
        }
        
        if (password !== passwordConfirm) {
            this.setBusy('a-create-key', false);
            this.toast('Пароли не совпадают', 'err');
            return;
        }

        console.log('=== Showing v-load ===');
        this.showView('v-load');
        this.setLoadingStatus('Создаём защищённый аккаунт', 'Генерируем уникальный ключ доступа');
        
        try {
            // Генерируем уникальный анонимный ключ
            const anonymousKey = this.generateAnonymousKey();
            console.log('=== Generated key:', anonymousKey);
            
            // Хешируем пароль
            this.setLoadingStatus('Укрепляем пароль', 'Считаем защитный хеш без отправки пароля');
            const passwordHash = await this.hashPassword(password);
            console.log('=== Password hashed ===');
            this.accessPasswordHash = passwordHash;
            
            // Сохраняем в localStorage
            // Сохраняем ключ
            this.setLoadingStatus('Готовим сейф', 'Создаём соль и ключи шифрования AES-256');
            this.anonymousKey = anonymousKey;
            console.log('=== Keys saved ===');
            localStorage.setItem('safekeys_anon_key', anonymousKey);
            this.salt = crypto.getRandomValues(new Uint8Array(16));
            this.key = await this.deriveKey(password, this.salt);
            this._currentPass = password;
            this.vault = [];
            this.notes = [];
            this.question = '';
            this.setLoadingStatus('Сохраняем в облако', 'Передаём только зашифрованный пустой сейф');
            const saved = await this.createVaultOnServer(passwordHash);
            if (!saved) throw new Error('Не удалось создать сейф на сервере');
            this.saveGuardSettings();
            await this.saveGuardSettingsToServer();
            
            // Очищаем поля
            this.$('register-password').value = '';
            this.$('register-password-confirm').value = '';
            
            console.log('=== Showing generated key modal ===');
            // Показываем ключ пользователю
            this.showGeneratedKey(anonymousKey);
            
        } catch (error) {
            console.error('=== Auth create error:', error);
            this.showView('v-menu');
            this.showError('Ошибка: ' + error.message);
        } finally {
            this.setBusy('a-create-key', false);
        }
    }

    showGeneratedKey(key) {
        // Показываем модальное окно с ключом
        const modal = document.createElement('div');
        modal.className = 'ov ov--on';
        modal.innerHTML = `
            <div class="ov__box" style="max-width: 500px;">
                <h2 style="color: #00ff88; margin-bottom: 20px; text-align: center;">Ваш уникальный ключ</h2>
                <div style="background: rgba(0,255,136,0.1); border: 2px solid #00ff88; border-radius: 8px; padding: 18px; margin: 20px 0; font-family: 'JetBrains Mono', monospace; font-size: 14px; text-align: center; overflow-wrap: anywhere; word-break: break-word; line-height: 1.35; color: #00ff88;">
                    <code style="font-family: inherit; font-size: inherit; color: inherit; background: transparent;">${key}</code>
                </div>
                <div style="background: rgba(255,100,100,0.1); border-left: 3px solid #ff6464; padding: 15px; margin: 20px 0; font-size: 13px; border-radius: 4px;">
                    <strong style="color: #ff6464;">КРИТИЧЕСКИ ВАЖНО:</strong><br><br>
                    <div style="line-height: 1.8;">
                    • Сохраните этот ключ в надежном месте<br>
                    • Без него вы не сможете войти в систему<br>
                    • Ключ невозможно восстановить<br>
                    • Никому не передавайте этот ключ<br>
                    • Используйте для входа с любого устройства
                    </div>
                </div>
                <button id="copy-key-btn" class="btn btn--w" style="width: 100%; margin-bottom: 10px;">Копировать ключ</button>
                <button id="confirm-key-btn" class="btn btn--o" style="width: 100%;">Я сохранил ключ, продолжить</button>
            </div>
        `;
        document.body.appendChild(modal);
        
        const copyBtn = document.getElementById('copy-key-btn');
        const confirmBtn = document.getElementById('confirm-key-btn');
        
        if (copyBtn) {
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(key);
                this.toast('Ключ скопирован в буфер обмена!', 'ok');
            };
        }
        
        if (confirmBtn) {
            confirmBtn.onclick = () => {
                document.body.removeChild(modal);
                console.log('User confirmed key, transitioning to master password setup');
                // Переходим к настройке мастер-пароля
                this.isNew = true;
                const ph = this.$('ph');
                const pq = this.$('pq');
                const pwWarn = this.$('pw-warn');
                if (ph) ph.textContent = 'Шаг 1: Задайте секретный вопрос и ответ';
                if (pq) pq.hidden = false;
                if (pwWarn) pwWarn.hidden = false;
                this.showView('v-master');
            };
        }
    }

    async authLoginWithKey() {
        if (!this.ensureSupabase()) return;
        this.setBusy('a-login-key', true);
        const rememberedKey = localStorage.getItem('safekeys_anon_key') || '';
        const keyInput = (this.$('auth-key').value.trim() || rememberedKey).toUpperCase();
        const password = this.$('auth-password').value.trim();
        
        if (!keyInput) {
            this.setBusy('a-login-key', false);
            this.toast('Введите ваш уникальный ключ', 'err');
            return;
        }
        
        if (!password) {
            this.setBusy('a-login-key', false);
            this.toast('Введите пароль доступа', 'err');
            return;
        }
        
        if (!keyInput.match(/^SK-[0-9A-F]{4}(-[0-9A-F]{4}){9}$/)) {
            this.setBusy('a-login-key', false);
            this.toast('Неверный формат ключа', 'err');
            return;
        }
        
        this.showView('v-load');
        this.setLoadingStatus('Проверяем доступ', 'Ищем сейф по вашему ключу');
        
        try {
            this.setLoadingStatus('Проверяем пароль', 'Пароль не отправляется, сверяется только хеш');
            const passwordHash = await this.hashPassword(password);
            this.setLoadingStatus('Подключаем сейф', 'Получаем зашифрованные данные из облака');
            const attempt = await this.authAttemptWithGuard(keyInput, passwordHash);
            if (!attempt.ok) {
                if (attempt.reason === 'locked') {
                    this.showView('v-menu');
                    const ms = Math.max(0, (attempt.lockedUntil || 0) - Date.now());
                    this.showError('Аккаунт временно заморожен. Осталось: ' + this.formatDuration(ms));
                } else if (attempt.reason === 'wiped') {
                    localStorage.setItem('safekeys_anon_key', keyInput);
                    this.showAccountDeletedNotice();
                } else if (attempt.reason === 'deleted') {
                    localStorage.setItem('safekeys_anon_key', keyInput);
                    this.showAccountDeletedNotice();
                } else if (localStorage.getItem('safekeys_anon_key') === keyInput && !attempt.remainingAttempts) {
                    this.showAccountDeletedNotice();
                } else {
                    this.showView('v-menu');
                    const tail = attempt.remainingAttempts ? ` Осталось попыток: ${attempt.remainingAttempts}` : '';
                    this.showError('Ключ или пароль неверные.' + tail);
                }
                return;
            }
            
            this.anonymousKey = keyInput;
            this.accessPasswordHash = passwordHash;
            this.guardFailedAttempts = 0;
            this.guardLockedUntil = 0;
            if (attempt.row?.guard_max_attempts) {
                this.guardMaxAttempts = Number(attempt.row.guard_max_attempts) || this.guardMaxAttempts;
                this.guardAction = attempt.row.guard_action === 'wipe' ? 'wipe' : 'lock';
                this.guardLockMinutes = Number(attempt.row.guard_lock_minutes) || this.guardLockMinutes;
            }
            this.saveGuardSettings();
            localStorage.setItem('safekeys_anon_key', keyInput);
            await this.unlockWithAccountPassword(password, attempt.row);
            
        } catch (error) {
            this.showView('v-menu');
            this.showError('Ошибка входа: ' + (error.message || error.details || ''));
        } finally {
            this.setBusy('a-login-key', false);
        }
    }

    async unlockWithAccountPassword(password, vaultRow = null) {
        this.showView('v-load');
        this.setLoadingStatus('Открываем сейф', 'Подготавливаем ключ расшифровки');
        try {
            if (vaultRow) {
                const data = vaultRow;
                if (!data.salt || !data.encrypted_data) {
                    this.setLoadingStatus('Инициализируем сейф', 'Создаём первое защищённое состояние');
                    this.salt = crypto.getRandomValues(new Uint8Array(16));
                    this.key = await this.deriveKey(password, this.salt);
                    this._currentPass = password;
                    this.vault = [];
                    this.notes = [];
                    this.question = '';
                    const saved = await this.save();
                    if (!saved) throw new Error('Не удалось инициализировать сейф');
                    this.goToDash();
                    this.resetAutoLock();
                    return;
                }

                this.setLoadingStatus('Расшифровываем данные', 'Проверяем целостность и открываем хранилище');
                this.salt = await this.fromB64(data.salt);
                this.key = await this.deriveKey(password, this.salt);
                if (data.mac) {
                    const expectedMac = await this.computeMac(data.encrypted_data, data.salt || '', data.question || '');
                    if (expectedMac !== data.mac) throw new Error('Данные повреждены или подменены');
                }
                const dec = await this.decrypt(data.encrypted_data);
                if (!dec) throw new Error('Не удалось расшифровать сейф этим паролем');
                this.vault = dec.vault || [];
                this.notes = dec.notes || [];
                this.question = data.question || '';
                this._currentPass = password;
                if (!data.mac) await this.save();
                this.goToDash();
                this.resetAutoLock();
                return;
            }
            const data = await this.getVaultRow(this.accessPasswordHash);
            if (!data) throw new Error('Сейф не найден на сервере');

            if (!data.salt || !data.encrypted_data) {
                this.setLoadingStatus('Инициализируем сейф', 'Создаём первое защищённое состояние');
                this.salt = crypto.getRandomValues(new Uint8Array(16));
                this.key = await this.deriveKey(password, this.salt);
                this._currentPass = password;
                this.vault = [];
                this.notes = [];
                this.question = '';
                const saved = await this.save();
                if (!saved) throw new Error('Не удалось инициализировать сейф');
                this.goToDash();
                this.resetAutoLock();
                return;
            }

            this.setLoadingStatus('Расшифровываем данные', 'Проверяем целостность и открываем хранилище');
            this.salt = await this.fromB64(data.salt);
            this.key = await this.deriveKey(password, this.salt);
            if (data.mac) {
                const expectedMac = await this.computeMac(data.encrypted_data, data.salt || '', data.question || '');
                if (expectedMac !== data.mac) throw new Error('Данные повреждены или подменены');
            }
            const dec = await this.decrypt(data.encrypted_data);
            if (!dec) throw new Error('Не удалось расшифровать сейф этим паролем');

            this.vault = dec.vault || [];
            this.notes = dec.notes || [];
            this.question = data.question || '';
            this._currentPass = password;
            if (!data.mac) await this.save();
            this.goToDash();
            this.resetAutoLock();
        } catch (error) {
            console.error(error);
            this.key = null;
            this.showView('v-menu');
            this.showError(error.message || 'Ошибка входа');
        }
    }

    async authSignOut() {
        // Удаляем анонимный ключ
        this.anonymousKey = null;
        this.lock();
    }

    async submitPass() {
        if (!this.anonymousKey) return;
        this.loadGuardSettings();
        const remainingMs = this.getGuardRemainingMs();
        if (remainingMs > 0) {
            this.showError('Аккаунт временно заморожен. Осталось: ' + this.formatDuration(remainingMs));
            return;
        }
        const p = this.$('pw').value; if (!p) return; 
        this.setBusy('a-go', true);
        this.$('pw').value = ''; this.showView('v-load');
        this.setLoadingStatus(this.isNew ? 'Создаём мастер-ключ' : 'Открываем сейф', this.isNew ? 'Собираем параметры шифрования' : 'Готовим расшифровку данных');
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));

        if (this.isNew) {
            // New Vault Setup
            try {
                this.question = this.$('pq').value.trim();
                this.setLoadingStatus('Создаём мастер-ключ', 'Производим ключи AES-256 и HMAC');
                this.salt = crypto.getRandomValues(new Uint8Array(16));
                this.key = await this.deriveKey(p, this.salt);
                this._currentPass = p;
                this.vault = []; this.notes = [];
                this.setLoadingStatus('Сохраняем сейф', 'Записываем только зашифрованные данные');
                const success = await this.save();
                if (success) this.goToDash();
            } catch(e) { 
                console.error(e); this.showView('v-master'); this.showError('Ошибка создания ключа'); 
            } finally {
                this.setBusy('a-go', false);
            }
        } else {
            // Existing Vault Unlock
            try {
                this.setLoadingStatus('Загружаем сейф', 'Получаем зашифрованный контейнер');
                const data = await this.getVaultRow(this.accessPasswordHash);
            if (!data) throw new Error('Сейф не найден в облаке');
                
                this.setLoadingStatus('Расшифровываем сейф', 'Проверяем мастер-пароль локально');
                this.salt = await this.fromB64(data.salt);
                this.key = await this.deriveKey(p, this.salt);
                
                const dec = await this.decrypt(data.encrypted_data);
                if (!dec) {
                    this.key = null;
                    const guard = await this.triggerLocalGuardFailure();
                    if (guard.reason === 'wiped') this.showAccountDeletedNotice();
                    else {
                        this.showView('v-master');
                        if (guard.reason === 'locked') this.showError('Неверный мастер-пароль. Аккаунт заморожен на ' + this.formatDuration((guard.lockedUntil || 0) - Date.now()));
                        else this.showError('Неверный мастер-пароль. Осталось попыток: ' + guard.remainingAttempts);
                    }
                    return;
                }
                
                this.vault = dec.vault || [];
                this.notes = dec.notes || [];
                this._currentPass = p;
                this.resetLocalGuardFailures();
                this.goToDash();
                this.resetAutoLock();
            } catch(e) {
                console.error(e);
                this.key = null;
                this.showView('v-master');
                this.showError(e.message || 'Ошибка расшифровки');
            } finally {
                this.setBusy('a-go', false);
            }
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
                this.syncKey = sk;
                this.deviceBound = true; this.vault = dec.vault || []; this.notes = dec.notes || []; this._currentPass = p; this.goToDash(); this.resetAutoLock();
            } catch {
                this.showView('v-pass'); this.$('ph').textContent = 'Введите мастер-пароль'; this.$('pw').focus(); this.showError('Неверный ключ синхронизации');
            }
        };
        this.$('a-sync-key-cx').onclick = () => { this.$('modal-sync-key').classList.remove('ov--on'); this.showView('v-pass'); this.$('pw').focus(); };
    }
    async resetKey() { const ok = await this.ask('Удалить сохранённый ключ из этого браузера?', 'Удаление ключа'); if (!ok) return; this.clearLocalVaultSession(); this.refreshKeyBadge(); this.showError('Ключ удалён только на этом устройстве.'); }

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

    async deriveKeys(pw, s) {
        const base = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(pw),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const params = { name: 'PBKDF2', salt: s, iterations: 100000, hash: 'SHA-256' };

        const aesKey = await crypto.subtle.deriveKey(
            params,
            base,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const macKey = await crypto.subtle.deriveKey(
            params,
            base,
            { name: 'HMAC', hash: 'SHA-256', length: 256 },
            false,
            ['sign', 'verify']
        );

        return { aesKey, macKey };
    }

    async deriveKey(pw, s) {
        const { aesKey, macKey } = await this.deriveKeys(pw, s);
        this.macKey = macKey;
        return aesKey;
    }

    async computeMac(encryptedDataStr, saltB64, questionStr) {
        if (!this.macKey) throw new Error('Missing mac key');
        const payload = `${saltB64 || ''}\n${questionStr || ''}\n${encryptedDataStr || ''}`;
        const sig = await crypto.subtle.sign('HMAC', this.macKey, new TextEncoder().encode(payload));
        return this.toB64(new Uint8Array(sig));
    }
    async encrypt(d) { const iv = crypto.getRandomValues(new Uint8Array(12)); const e = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, new TextEncoder().encode(JSON.stringify(d))); return { c: await this.toB64(new Uint8Array(e)), i: await this.toB64(iv) }; }
    async decrypt(o) { try { if (typeof o === 'string') o = JSON.parse(o); const iv = await this.fromB64(o.i); const ct = await this.fromB64(o.c); return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, ct))); } catch { return null; } }

    // === SAVE — PRIMARY storage is now Supabase ===
    async createVaultOnServer(passwordHash) {
        if (!this.anonymousKey || !this.key || !this.ensureSupabase()) return false;
        const encrypted = await this.encrypt({ vault: this.vault, notes: this.notes });
        const saltB64 = await this.toB64(this.salt);
        const mac = await this.computeMac(JSON.stringify(encrypted), saltB64, this.question || '');
        return await this.withMacFallback(async () => {
            const { data } = await this.rpcOrTable({
                rpc: 'safekeys_create_vault',
                params: {
                    p_anonymous_key: this.anonymousKey,
                    p_password_hash: passwordHash,
                    p_encrypted_data: JSON.stringify(encrypted),
                    p_salt: saltB64,
                    p_question: this.question || '',
                    p_mac: mac
                },
                tableOp: () => {
                    const row = {
                        anonymous_key: this.anonymousKey,
                        password_hash: passwordHash,
                        encrypted_data: JSON.stringify(encrypted),
                        salt: saltB64,
                        question: this.question || ''
                    };
                    if (this._hasMacColumn) row.mac = mac;
                    return this.supabase
                        .from('vaults')
                        .upsert(row, { onConflict: 'anonymous_key' })
                        .select('anonymous_key');
                }
            });
            return Array.isArray(data) && data.length > 0;
        });
    }

    async save() {
        if (!this.anonymousKey || !this.key) return false;
        if (!this.ensureSupabase()) return false;
        
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
        
        try {
            const e = await this.encrypt({ vault: this.vault, notes: this.notes });
            if (!this.accessPasswordHash) throw new Error('Missing access hash');
            const saltB64 = await this.toB64(this.salt);
            const mac = await this.computeMac(JSON.stringify(e), saltB64, this.question || '');
            const ok = await this.withMacFallback(async () => {
                const { data } = await this.rpcOrTable({
                    rpc: 'safekeys_update_vault',
                    params: {
                        p_anonymous_key: this.anonymousKey,
                        p_password_hash: this.accessPasswordHash,
                        p_encrypted_data: JSON.stringify(e),
                        p_salt: saltB64,
                        p_question: this.question || '',
                        p_mac: mac
                    },
                    tableOp: () => {
                        const update = {
                            encrypted_data: JSON.stringify(e),
                            salt: saltB64,
                            question: this.question || '',
                            updated_at: new Date().toISOString()
                        };
                        if (this._hasMacColumn) update.mac = mac;
                        return this.supabase
                            .from('vaults')
                            .update(update)
                            .eq('anonymous_key', this.anonymousKey)
                            .eq('password_hash', this.accessPasswordHash)
                            .select('anonymous_key');
                    }
                });
                return !!(data && data.length);
            });
            if (!ok) throw new Error('Vault update rejected');
            
            this.recalcStorage();
            return true;
        } catch(e) {
            console.error(e);
            this.toast('Ошибка синхронизации с облаком', 'err');
            return false;
        }
    }

    async loadVaultFromDB() {
        if (!this.anonymousKey || !this.accessPasswordHash || !this.ensureSupabase()) return null;
        const row = await this.getVaultRow(this.accessPasswordHash);
        if (!row) return null;
        return JSON.stringify({ s: row.salt || '', v: row.encrypted_data || '', q: row.question || '', m: row.mac || '' });
    }

    async saveVaultToDB(raw) {
        if (!this.anonymousKey || !this.accessPasswordHash || !this.ensureSupabase()) return false;
        const parsed = JSON.parse(raw);
        const vStr = typeof parsed.v === 'string' ? parsed.v : JSON.stringify(parsed.v || '');
        const mac = await this.computeMac(vStr, parsed.s || '', parsed.q || '');
        return await this.withMacFallback(async () => {
            const { data } = await this.rpcOrTable({
                rpc: 'safekeys_update_vault',
                params: {
                    p_anonymous_key: this.anonymousKey,
                    p_password_hash: this.accessPasswordHash,
                    p_encrypted_data: vStr,
                    p_salt: parsed.s || '',
                    p_question: parsed.q || '',
                    p_mac: mac
                },
                tableOp: () => {
                    const update = {
                        encrypted_data: vStr,
                        salt: parsed.s || '',
                        question: parsed.q || '',
                        updated_at: new Date().toISOString()
                    };
                    if (this._hasMacColumn) update.mac = mac;
                    return this.supabase
                        .from('vaults')
                        .update(update)
                        .eq('anonymous_key', this.anonymousKey)
                        .eq('password_hash', this.accessPasswordHash)
                        .select('anonymous_key');
                }
            });
            return Array.isArray(data) && data.length > 0;
        });
    }

    clearLocalVaultSession() {
        const key = this.anonymousKey;
        localStorage.removeItem('safekeys_anon_key');
        if (key) localStorage.removeItem(this.guardStorageKey(key));
        this.anonymousKey = null;
        this.lock();
    }

    async wipeAccountFromDB() {
        const key = this.anonymousKey;
        const hash = this.accessPasswordHash;
        if (key && hash && this.supabase) {
            try {
                await this.supabase.rpc('safekeys_delete_vault', {
                    p_anonymous_key: key,
                    p_password_hash: hash
                });
            } catch {}
        }
        if (key) {
            localStorage.setItem('safekeys_anon_key', key);
            localStorage.removeItem(this.guardStorageKey(key));
        }
        this.lock();
    }

    async clearVaultFromDB() {
        await this.wipeAccountFromDB();
    }

    saveFileHandleToDB() {}
    clearFileHandleFromDB() {}
    refreshKeyBadge() {}

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

    switchTab(tab) {
        if (!tab) return;
        this.activeTab = tab;

        document.querySelectorAll('.tab').forEach(btn => {
            btn.classList.toggle('tab--active', btn.dataset.tab === tab);
        });

        const sections = {
            passwords: this.$('sec-passwords'),
            '2fa': this.$('sec-2fa'),
            notes: this.$('sec-notes'),
            audit: this.$('sec-audit')
        };

        Object.entries(sections).forEach(([name, el]) => {
            if (el) el.hidden = name !== tab;
        });

        if (tab === 'passwords') this.renderPasswords();
        if (tab === '2fa') this.render2FA();
        if (tab === 'notes') this.renderNotes();
        if (tab === 'audit') this.renderAudit();
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
            const c = document.createElement('div'); c.className = 'card'; c.dataset.id = i.id;
            c.onclick = () => this.openDetail(i);
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
        this.$('p-title').textContent = 'Р едактирование'; 
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
    
    // QR/image import removed
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
    stripMediaFromHtml(html) {
        const tmp = document.createElement('div');
        tmp.innerHTML = html || '';
        tmp.querySelectorAll('img,video,audio,source,track,picture,iframe,object,embed').forEach(el => el.remove());
        // remove inline media-ish attributes
        tmp.querySelectorAll('[src],[srcset]').forEach(el => { el.removeAttribute('src'); el.removeAttribute('srcset'); });
        return tmp.innerHTML;
    }

    renderNotes() {
        const q = this.$('qn').value.toLowerCase();
        let l = this.notes.filter(x => x.title.toLowerCase().includes(q) || (x.plain || '').toLowerCase().includes(q));
        l.sort((a, b) => b.ts - a.ts);
        const g = this.$('notes-grid'); g.innerHTML = ''; this.$('empty-notes').hidden = l.length > 0;
        l.forEach(i => {
            const c = document.createElement('div'); c.className = 'card card--note'; c.dataset.id = i.id;
            c.onclick = () => this.openNoteDetail(i);
            const plain = (i.plain || '').substring(0, 120);
            c.innerHTML = `<div class="card__top"><span class="card__name">${this.h(i.title)}</span><span class="card__date">${new Date(i.ts).toLocaleDateString('ru-RU')}</span></div><div class="card__excerpt">${this.h(plain)}</div>`;
            g.appendChild(c);
        });
    }
    openNoteModal(item = null) {
        this.$('mn-title').textContent = item ? 'Р едактировать' : 'Новая заметка';
        this.$('n-id').value = item?.id || ''; this.$('n-name').value = item?.title || '';
        this.$('n-editor').innerHTML = item?.html || item?.text || '';
        this.$('modal-note').classList.add('ov--on');
    }
    async saveNote(e) {
        e.preventDefault(); const id = this.$('n-id').value;
        const rawHtml = this.$('n-editor').innerHTML;
        const html = this.stripMediaFromHtml(rawHtml);
        const tmp = document.createElement('div'); tmp.innerHTML = html;
        const note = { id: id || Date.now().toString(), title: this.$('n-name').value, html, plain: tmp.textContent, ts: Date.now() };
        if (id) { const i = this.notes.findIndex(x => x.id === id); if (i >= 0) this.notes[i] = note; } else this.notes.push(note);
        await this.save(); this.closeModal('modal-note'); this.renderNotes(); this.toast('Заметка сохранена', 'ok');
    }
    openNoteDetail(i) {
        this.currentItem = i;
        this.$('p-title').textContent = i.title; this.$('p-view').hidden = false; this.$('p-edit').hidden = true;
        const date = new Date(i.ts).toLocaleString('ru-RU');

        const safeHtml = this.stripMediaFromHtml(i.html || '');
        let h = `<div class="detail-note">${safeHtml || this.h(i.text || '')}</div>`;
        h += `<div class="detail-meta">`;
        h += `<span class="detail-meta__item">Изменено: ${date}</span>`;
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
