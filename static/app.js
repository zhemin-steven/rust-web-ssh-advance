/**
 * Web SSH Client
 * Author: steven
 * A simple web-based SSH client using xterm.js and Rust backend
 */

// Check authentication
const authToken = localStorage.getItem('auth_token');
const username = localStorage.getItem('username');

if (!authToken) {
    window.location.href = '/login.html';
}

// Verify token
fetch('/api/auth/verify', {
    headers: {
        'Authorization': `Bearer ${authToken}`,
    },
})
.then(res => res.json())
.then(data => {
    if (!data.username) {
        localStorage.clear();
        window.location.href = '/login.html';
    } else {
        // Display user info
        document.getElementById('user-display').textContent = `👤 ${data.username}`;
    }
})
.catch(() => {
    localStorage.clear();
    window.location.href = '/login.html';
});

// Language switcher
document.getElementById('language-btn').addEventListener('click', () => {
    const newLang = i18n.getLanguage() === 'zh-CN' ? 'en-US' : 'zh-CN';
    i18n.setLanguage(newLang);
    // Reload saved configs to update language
    loadSavedConfigs();
});

// Listen for language change events to update dynamic content
window.addEventListener('languageChanged', () => {
    // Reload saved configs to update language
    loadSavedConfigs();
});

// Logout handler
document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.clear();
    window.location.href = '/login.html';
});

// Change password modal handlers
document.getElementById('change-password-btn').addEventListener('click', () => {
    document.getElementById('change-password-modal').style.display = 'flex';
    document.getElementById('change-password-form').reset();
});

document.getElementById('close-change-password').addEventListener('click', () => {
    document.getElementById('change-password-modal').style.display = 'none';
});

document.getElementById('cancel-change-password').addEventListener('click', () => {
    document.getElementById('change-password-modal').style.display = 'none';
});

// Close modal when clicking outside
document.getElementById('change-password-modal').addEventListener('click', (e) => {
    if (e.target.id === 'change-password-modal') {
        document.getElementById('change-password-modal').style.display = 'none';
    }
});

// Change password form handler
document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    // Validate passwords
    if (newPassword !== confirmPassword) {
        alert(i18n.t('password.mismatch'));
        return;
    }

    if (newPassword.length < 6) {
        alert(i18n.t('password.too.short'));
        return;
    }

    if (newPassword === currentPassword) {
        alert(i18n.t('password.same.as.old'));
        return;
    }

    const token = localStorage.getItem('auth_token');

    try {
        const response = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({
                old_password: currentPassword,
                new_password: newPassword,
            }),
        });

        const data = await response.json();

        if (data.success) {
            alert('✅ ' + i18n.t('password.change.success'));
            localStorage.clear();
            window.location.href = '/login.html';
        } else {
            alert('❌ ' + i18n.t('password.change.error') + ': ' + (data.error || i18n.t('error.unknown')));
        }
    } catch (error) {
        console.error('Failed to change password:', error);
        alert('❌ ' + i18n.t('password.change.error'));
    }
});

// 2FA modal handlers
document.getElementById('totp-btn').addEventListener('click', async () => {
    await showTotpModal();
});

document.getElementById('close-totp').addEventListener('click', () => {
    document.getElementById('totp-modal').style.display = 'none';
});

document.getElementById('totp-modal').addEventListener('click', (e) => {
    if (e.target.id === 'totp-modal') {
        document.getElementById('totp-modal').style.display = 'none';
    }
});

// Show TOTP modal and check status
async function showTotpModal() {
    const token = localStorage.getItem('auth_token');

    try {
        const response = await fetch('/api/auth/totp/status', {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        const data = await response.json();

        if (data.error) {
            alert(i18n.t('totp.status.error') + ': ' + data.error);
            return;
        }

        // Show modal
        document.getElementById('totp-modal').style.display = 'flex';

        // Reset views
        document.getElementById('totp-status-view').style.display = 'block';
        document.getElementById('totp-setup-view').style.display = 'none';
        document.getElementById('totp-disable-view').style.display = 'none';

        // Update status
        const statusText = document.getElementById('totp-status-text');
        const enableBtn = document.getElementById('enable-totp-btn');
        const disableBtn = document.getElementById('disable-totp-btn');

        if (data.enabled) {
            const msg = i18n.getLanguage() === 'zh-CN'
                ? '您的账号已受到双因素认证保护'
                : 'Your account is protected by two-factor authentication';
            statusText.innerHTML = `✅ <strong>${i18n.t('totp.enabled')}</strong><br><small style="color: #666;">${msg}</small>`;
            enableBtn.style.display = 'none';
            disableBtn.style.display = 'block';
        } else {
            const msg = i18n.getLanguage() === 'zh-CN'
                ? '建议启用双因素认证以提高账号安全性'
                : 'Enable 2FA to improve account security';
            statusText.innerHTML = `⚠️ <strong>${i18n.t('totp.disabled')}</strong><br><small style="color: #666;">${msg}</small>`;
            enableBtn.style.display = 'block';
            disableBtn.style.display = 'none';
        }
    } catch (error) {
        console.error('Failed to get TOTP status:', error);
        alert(i18n.t('totp.status.error'));
    }
}

// Enable TOTP button
document.getElementById('enable-totp-btn').addEventListener('click', async () => {
    const token = localStorage.getItem('auth_token');

    try {
        const response = await fetch('/api/auth/totp/setup', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        const data = await response.json();

        if (data.error) {
            alert(i18n.t('totp.setup.error') + ': ' + data.error);
            return;
        }

        // Show setup view
        document.getElementById('totp-status-view').style.display = 'none';
        document.getElementById('totp-setup-view').style.display = 'block';

        // Display QR code and secret
        document.getElementById('qr-code-image').src = data.qr_code;
        document.getElementById('totp-secret-text').textContent = data.secret;
        document.getElementById('totp-secret-hidden').value = data.secret;
        document.getElementById('enable-totp-form').reset();
        document.getElementById('totp-verify-code').value = '';
    } catch (error) {
        console.error('Failed to setup TOTP:', error);
        alert(i18n.t('totp.setup.error'));
    }
});

// Cancel TOTP setup
document.getElementById('cancel-totp-setup').addEventListener('click', () => {
    showTotpModal();
});

// Enable TOTP form submit
document.getElementById('enable-totp-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const token = localStorage.getItem('auth_token');
    const secret = document.getElementById('totp-secret-hidden').value;
    const code = document.getElementById('totp-verify-code').value;

    try {
        const response = await fetch('/api/auth/totp/enable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ secret, code }),
        });

        const data = await response.json();

        if (data.success) {
            alert('✅ ' + i18n.t('totp.enable.success'));
            document.getElementById('totp-modal').style.display = 'none';
        } else {
            alert('❌ ' + i18n.t('totp.enable.error') + ': ' + (data.error || i18n.t('error.unknown')));
        }
    } catch (error) {
        console.error('Failed to enable TOTP:', error);
        alert('❌ ' + i18n.t('totp.enable.error'));
    }
});

// Disable TOTP button
document.getElementById('disable-totp-btn').addEventListener('click', () => {
    document.getElementById('totp-status-view').style.display = 'none';
    document.getElementById('totp-disable-view').style.display = 'block';
    document.getElementById('disable-totp-form').reset();
});

// Cancel TOTP disable
document.getElementById('cancel-totp-disable').addEventListener('click', () => {
    showTotpModal();
});

// Disable TOTP form submit
document.getElementById('disable-totp-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const token = localStorage.getItem('auth_token');
    const password = document.getElementById('totp-disable-password').value;
    const code = document.getElementById('totp-disable-code').value;

    try {
        const response = await fetch('/api/auth/totp/disable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ password, code }),
        });

        const data = await response.json();

        if (data.success) {
            alert('✅ ' + i18n.t('totp.disable.success'));
            document.getElementById('totp-modal').style.display = 'none';
        } else {
            alert('❌ ' + i18n.t('totp.disable.error') + ': ' + (data.error || i18n.t('error.unknown')));
        }
    } catch (error) {
        console.error('Failed to disable TOTP:', error);
        alert('❌ ' + i18n.t('totp.disable.error'));
    }
});

// New connection button handler
document.getElementById('new-connection-btn').addEventListener('click', () => {
    showConnectionForm();
});

// Cancel form button handler
document.getElementById('cancel-form-btn').addEventListener('click', () => {
    hideConnectionForm();
});

// Show connection form
function showConnectionForm() {
    document.getElementById('ssh-form').style.display = 'block';
    document.getElementById('saved-configs').style.display = 'none';
    // Clear form
    document.getElementById('ssh-form').reset();
    document.getElementById('host').value = '127.0.0.1';
    document.getElementById('port').value = '22';
    document.getElementById('config-name').style.display = 'none';
}

// Hide connection form
function hideConnectionForm() {
    document.getElementById('ssh-form').style.display = 'none';
    document.getElementById('saved-configs').style.display = 'block';
}

// Audit log modal
const auditModal = document.getElementById('audit-modal');
const auditBtn = document.getElementById('audit-btn');
const closeAuditModal = document.getElementById('close-audit-modal');
const refreshAuditBtn = document.getElementById('refresh-audit');
const auditLimitSelect = document.getElementById('audit-limit');

auditBtn.addEventListener('click', () => {
    auditModal.style.display = 'flex';
    loadAuditLogs();
});

closeAuditModal.addEventListener('click', () => {
    auditModal.style.display = 'none';
});

auditModal.addEventListener('click', (e) => {
    if (e.target === auditModal) {
        auditModal.style.display = 'none';
    }
});

refreshAuditBtn.addEventListener('click', () => {
    loadAuditLogs();
});

auditLimitSelect.addEventListener('change', () => {
    loadAuditLogs();
});

// Load audit logs
async function loadAuditLogs() {
    const token = localStorage.getItem('auth_token');
    const limit = auditLimitSelect.value;
    const auditLogsContainer = document.getElementById('audit-logs');

    auditLogsContainer.innerHTML = `<p class="loading">${i18n.t('app.loading')}</p>`;

    try {
        const response = await fetch(`/api/audit/logs?limit=${limit}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        const data = await response.json();

        if (data.error) {
            auditLogsContainer.innerHTML = `<p class="no-logs">${i18n.t('error.server')}: ${data.error}</p>`;
            return;
        }

        if (!Array.isArray(data) || data.length === 0) {
            auditLogsContainer.innerHTML = `<p class="no-logs">${i18n.t('audit.no.logs')}</p>`;
            return;
        }

        auditLogsContainer.innerHTML = data.map(log => {
            const date = new Date(log.timestamp * 1000);
            const actionText = getActionText(log.action);
            const statusClass = log.success ? 'success' : 'failure';

            return `
                <div class="audit-log-item ${statusClass}">
                    <div class="audit-log-header">
                        <span class="audit-log-action">${actionText}</span>
                        <span class="audit-log-time">${date.toLocaleString()}</span>
                    </div>
                    <div class="audit-log-details">
                        <span class="audit-log-user">👤 ${escapeHtml(log.username)}</span>
                        ${log.target ? ` • -> : ${escapeHtml(log.target)}` : ''}
                        ${log.details ? ` • ${escapeHtml(log.details)}` : ''}
                        ${log.ip_address ? ` • IP: ${escapeHtml(log.ip_address)}` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load audit logs:', error);
        auditLogsContainer.innerHTML = '<p class="no-logs">加载失败</p>';
    }
}

// Get action text with i18n support
function getActionText(action) {
    const actionKey = `action.${action}`;
    const translated = i18n.t(actionKey);

    // If translation exists, add emoji prefix
    const emojiMap = {
        'Login': '🔐',
        'Logout': '🚪',
        'SshConnect': '🔌',
        'SshDisconnect': '🔌',
        'SshCommand': '⌨️',
        'CreateConfig': '➕',
        'UpdateConfig': '✏️',
        'DeleteConfig': '🗑️',
        'CreateUser': '👤',
        'DeleteUser': '👤',
    };

    const emoji = emojiMap[action] || '';
    return emoji ? `${emoji} ${translated}` : translated;
}

// Base64 encoding/decoding utilities (UTF-8 safe)
const utf8ToBase64 = (str) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return btoa(String.fromCharCode(...data));
};

const base64ToUtf8 = (str) => {
    const data = atob(str);
    const bytes = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        bytes[i] = data.charCodeAt(i);
    }
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
};

// Global variables
let terminal = null;
let socket = null;
let fitAddon = null;
let lastSelectionTime = 0;
let savedSelection = '';

// Copy text to clipboard (with fallback for older browsers)
async function copyText(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            // Fallback
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
        }
    } catch (err) {
        console.error('Copy failed:', err);
    }
}

// Load saved SSH configurations
async function loadSavedConfigs() {
    const token = localStorage.getItem('auth_token');
    try {
        const response = await fetch('/api/configs', {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        const configs = await response.json();

        const configList = document.getElementById('config-list');

        if (configs.error || configs.length === 0) {
            configList.innerHTML = `<p class="no-configs">${i18n.t('ssh.no.saved.connections')}</p>`;
            return;
        }

        const lastUsedText = i18n.getLanguage() === 'zh-CN' ? '最后使用' : 'Last used';
        const connectText = i18n.t('ssh.connect');
        const deleteText = i18n.t('common.delete');

        configList.innerHTML = configs.map(config => `
            <div class="config-item">
                <div class="config-info">
                    <div class="config-name">${escapeHtml(config.name)}</div>
                    <div class="config-details">
                        ${escapeHtml(config.username)}@${escapeHtml(config.host)}:${config.port}
                        ${config.last_used ? ` • ${lastUsedText}: ${new Date(config.last_used * 1000).toLocaleString()}` : ''}
                    </div>
                </div>
                <div class="config-actions">
                    <button class="btn-use" onclick="useConfig('${config.id}')">${connectText}</button>
                    <button class="btn-delete" onclick="deleteConfig('${config.id}')">${deleteText}</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load configs:', error);
        configList.innerHTML = `<p class="no-configs">${i18n.t('config.load.error')}</p>`;
    }
}

// Use a saved configuration (directly connect)
async function useConfig(configId) {
    const token = localStorage.getItem('auth_token');
    try {
        const response = await fetch(`/api/configs/${configId}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        const config = await response.json();

        if (config.error) {
            alert(i18n.t('config.load.error') + ': ' + config.error);
            return;
        }

        // Directly connect using the saved config
        connectSSH({
            host: config.host,
            port: config.port,
            username: config.username,
            auth_type: config.auth_type,
            password: config.password || '',
            private_key: config.private_key || '',
            passphrase: config.passphrase || '',
        });
    } catch (error) {
        console.error('Failed to use config:', error);
        alert(i18n.t('config.load.error'));
    }
}

// Delete a saved configuration
async function deleteConfig(configId) {
    if (!confirm(i18n.t('config.delete.confirm'))) {
        return;
    }

    const token = localStorage.getItem('auth_token');
    try {
        const response = await fetch(`/api/configs/${configId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        const result = await response.json();

        if (result.success) {
            loadSavedConfigs();
        } else {
            alert(i18n.t('config.delete.error') + ': ' + (result.error || i18n.t('error.unknown')));
        }
    } catch (error) {
        console.error('Failed to delete config:', error);
        alert(i18n.t('config.delete.error'));
    }
}

// Save current configuration
async function saveCurrentConfig(configData) {
    const token = localStorage.getItem('auth_token');
    try {
        const response = await fetch('/api/configs', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(configData),
        });
        const result = await response.json();

        if (result.id) {
            loadSavedConfigs();
            return true;
        } else {
            alert(i18n.t('config.save.error') + ': ' + (result.error || i18n.t('error.unknown')));
            return false;
        }
    } catch (error) {
        console.error('Failed to save config:', error);
        alert(i18n.t('config.save.error'));
        return false;
    }
}

// HTML escape utility
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Expose functions to global scope for onclick handlers
window.useConfig = useConfig;
window.deleteConfig = deleteConfig;

// Load configs on page load
loadSavedConfigs();

// DOM elements
const connectForm = document.getElementById('connect-form');
const terminalContainer = document.getElementById('terminal-container');
const sshForm = document.getElementById('ssh-form');
const disconnectBtn = document.getElementById('disconnect-btn');
const connectionInfo = document.getElementById('connection-info');

// Authentication method toggle
const authRadios = document.querySelectorAll('input[name="auth"]');
const passwordGroup = document.getElementById('password-group');
const keyGroup = document.getElementById('key-group');
const passphraseGroup = document.getElementById('passphrase-group');

authRadios.forEach(radio => {
    radio.addEventListener('change', (e) => {
        if (e.target.value === 'password') {
            passwordGroup.style.display = 'block';
            keyGroup.style.display = 'none';
            passphraseGroup.style.display = 'none';
        } else {
            passwordGroup.style.display = 'none';
            keyGroup.style.display = 'block';
            passphraseGroup.style.display = 'block';
        }
    });
});

// Save config checkbox toggle
const saveConfigCheckbox = document.getElementById('save-config');
const configNameInput = document.getElementById('config-name');

saveConfigCheckbox.addEventListener('change', (e) => {
    if (e.target.checked) {
        configNameInput.style.display = 'block';
        configNameInput.required = true;
    } else {
        configNameInput.style.display = 'none';
        configNameInput.required = false;
    }
});

// Private key file reading
const keyFileInput = document.getElementById('key-file');
const privateKeyTextarea = document.getElementById('private-key');

keyFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
            privateKeyTextarea.value = event.target.result;
        };
        reader.readAsText(file);
    }
});

// Form submission
sshForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const host = document.getElementById('host').value;
    const port = document.getElementById('port').value;
    const username = document.getElementById('username').value;
    const authType = document.querySelector('input[name="auth"]:checked').value;

    let password = '';
    let privateKey = '';

    if (authType === 'password') {
        password = document.getElementById('password').value;
        if (!password) {
            alert(i18n.t('form.password.required'));
            return;
        }
    } else {
        privateKey = privateKeyTextarea.value;
        if (!privateKey) {
            alert(i18n.t('form.key.required'));
            return;
        }
        password = document.getElementById('passphrase').value;
    }

    // Save configuration if checkbox is checked
    if (saveConfigCheckbox.checked) {
        const configName = configNameInput.value.trim();
        if (!configName) {
            alert(i18n.t('form.config.name.required'));
            return;
        }

        const configData = {
            name: configName,
            host,
            port: parseInt(port),
            username,
            auth_type: authType,
        };

        // Only save password for password auth
        if (authType === 'password') {
            configData.password = password;
        }

        await saveCurrentConfig(configData);

        // Reset checkbox and name input
        saveConfigCheckbox.checked = false;
        configNameInput.value = '';
        configNameInput.style.display = 'none';
    }

    connectSSH({
        host,
        port,
        username,
        auth_type: authType,
        password,
        private_key: privateKey
    });
});

// Disconnect
disconnectBtn.addEventListener('click', () => {
    if (socket) {
        socket.close();
    }
    showConnectForm();
});

// Show connection form
function showConnectForm() {
    connectForm.style.display = 'flex';
    terminalContainer.style.display = 'none';

    // 恢复 body 滚动
    document.body.style.overflow = '';
    document.body.style.position = '';
    document.body.style.width = '';
    document.body.style.height = '';

    if (terminal) {
        terminal.dispose();
        terminal = null;
    }
}

// Show terminal
function showTerminal() {
    connectForm.style.display = 'none';
    terminalContainer.style.display = 'flex';

    // 在移动端禁用 body 滚动，防止页面滚动干扰终端
    document.body.style.overflow = 'hidden';
    document.body.style.position = 'fixed';
    document.body.style.width = '100%';
    document.body.style.height = '100%';
}

// Connect to SSH
function connectSSH(config) {
    // Initialize terminal
    terminal = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'Courier New, monospace',
        theme: {
            background: '#1e1e1e',
            foreground: '#d4d4d4',
            cursor: '#ffffff',
            black: '#000000',
            red: '#cd3131',
            green: '#0dbc79',
            yellow: '#e5e510',
            blue: '#2472c8',
            magenta: '#bc3fbc',
            cyan: '#11a8cd',
            white: '#e5e5e5',
            brightBlack: '#666666',
            brightRed: '#f14c4c',
            brightGreen: '#23d18b',
            brightYellow: '#f5f543',
            brightBlue: '#3b8eea',
            brightMagenta: '#d670d6',
            brightCyan: '#29b8db',
            brightWhite: '#e5e5e5'
        },
        cols: 80,
        rows: 24,
        allowTransparency: false,
        scrollback: 1000
    });

    // Load fit addon
    fitAddon = new FitAddon.FitAddon();
    terminal.loadAddon(fitAddon);

    // Show terminal UI
    showTerminal();
    connectionInfo.textContent = `${config.username}@${config.host}:${config.port}`;

    // Open terminal
    const terminalElement = document.getElementById('terminal');
    terminal.open(terminalElement);

    // Handle keyboard events
    terminalElement.addEventListener('keydown', (e) => {
        // Ctrl+C / Cmd+C - Copy
        if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'C')) {
            const selection = savedSelection || terminal.getSelection();
            if (selection && selection.length > 0) {
                copyText(selection);
                lastSelectionTime = Date.now();
                savedSelection = '';
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
        }

        // Ctrl+V / Cmd+V - Paste
        else if ((e.ctrlKey || e.metaKey) && (e.key === 'v' || e.key === 'V')) {
            e.preventDefault();
            navigator.clipboard.readText().then(text => {
                if (socket && socket.readyState === WebSocket.OPEN) {
                    socket.send(JSON.stringify({
                        type: 'stdin',
                        data: utf8ToBase64(text)
                    }));
                }
            }).catch(err => console.error('Failed to read clipboard:', err));
            return false;
        }
    });

    // Track selection changes
    terminal.onSelectionChange(() => {
        const selection = terminal.getSelection();
        if (selection && selection.length > 0) {
            lastSelectionTime = Date.now();
            savedSelection = selection;
        } else {
            if (Date.now() - lastSelectionTime > 500) {
                savedSelection = '';
            }
        }
    });

    // Handle right-click for copy
    terminalElement.addEventListener('contextmenu', () => {
        setTimeout(() => {
            const selection = terminal.getSelection();
            if (selection && selection.length > 0) {
                copyText(selection);
            }
        }, 10);
    });

    // Fit terminal to container
    setTimeout(() => fitAddon.fit(), 100);

    terminal.writeln('正在连接到服务器...');

    // Establish WebSocket connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = localStorage.getItem('auth_token');
    const wsUrl = `${protocol}//${window.location.host}/api/ssh?token=${encodeURIComponent(token)}`;

    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        terminal.writeln('WebSocket 连接已建立');
        terminal.writeln(`正在连接到 ${config.username}@${config.host}:${config.port}...`);

        setTimeout(() => {
            fitAddon.fit();
            scrollTerminalToBottom();
        }, 200);

        // Send connection parameters
        socket.send(JSON.stringify({ type: 'addr', data: utf8ToBase64(`${config.host}:${config.port}`) }));
        socket.send(JSON.stringify({ type: 'login', data: utf8ToBase64(config.username) }));

        if (config.auth_type === 'password') {
            socket.send(JSON.stringify({ type: 'password', data: utf8ToBase64(config.password) }));
        } else {
            socket.send(JSON.stringify({ type: 'key', data: utf8ToBase64(config.private_key) }));
            if (config.passphrase) {
                socket.send(JSON.stringify({ type: 'password', data: utf8ToBase64(config.passphrase) }));
            }
        }

        // Send terminal size
        socket.send(JSON.stringify({
            type: 'resize',
            cols: terminal.cols,
            rows: terminal.rows
        }));

        // Send connect command
        socket.send(JSON.stringify({ type: 'connect', data: '' }));

        // Handle terminal input
        terminal.onData((data) => {
            if (socket && socket.readyState === WebSocket.OPEN) {
                const timeSinceSelection = Date.now() - lastSelectionTime;

                // Filter ^C from automatic Control key after selection
                if (data === '\x03' && timeSinceSelection < 500) {
                    return;
                }

                socket.send(JSON.stringify({
                    type: 'stdin',
                    data: utf8ToBase64(data)
                }));

                // 用户输入后也滚动到底部
                scrollTerminalThrottled();
            }
        });

        // Handle window resize
        window.addEventListener('resize', handleResize);
        setTimeout(() => {
            handleResize();
            scrollTerminalToBottom();
        }, 300);
    };

    socket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);

            switch (msg.type) {
                case 'stdout':
                    terminal.write(base64ToUtf8(msg.data));
                    // 使用节流版本避免频繁滚动
                    scrollTerminalThrottled();
                    break;
                case 'stderr':
                    terminal.write('\x1b[31m' + base64ToUtf8(msg.data) + '\x1b[0m');
                    // 使用节流版本避免频繁滚动
                    scrollTerminalThrottled();
                    break;
            }
        } catch (e) {
            console.error('解析消息失败:', e);
        }
    };

    socket.onerror = (error) => {
        console.error('WebSocket 错误:', error);
        terminal.writeln('\r\n\x1b[31mWebSocket 连接错误\x1b[0m');
    };

    socket.onclose = () => {
        terminal.writeln('\r\n\x1b[33m连接已关闭\x1b[0m');
        window.removeEventListener('resize', handleResize);
    };
}

// Debounce function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Scroll terminal to bottom - 确保光标可见（移动端优化）
let scrollPending = false;
function scrollTerminalToBottom() {
    if (!terminal || scrollPending) return;
    scrollPending = true;

    requestAnimationFrame(() => {
        try {
            terminal.scrollToBottom();
            const viewport = document.querySelector('.xterm-viewport');
            if (viewport) {
                viewport.scrollTop = viewport.scrollHeight + 100; // 额外偏移确保光标可见
            }

            // 延迟再次确保（处理异步渲染）
            setTimeout(() => {
                if (terminal) terminal.scrollToBottom();
                if (viewport) viewport.scrollTop = viewport.scrollHeight + 100;
                scrollPending = false;
            }, 100);
        } catch (e) {
            scrollPending = false;
        }
    });
}

// 节流版本 - 避免频繁滚动影响性能
const scrollTerminalThrottled = debounce(scrollTerminalToBottom, 100);

// Handle window resize
const handleResize = debounce(() => {
    if (terminal && fitAddon) {
        try {
            fitAddon.fit();

            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({
                    type: 'resize',
                    cols: terminal.cols,
                    rows: terminal.rows
                }));
            }

            // 调整大小后滚动到底部
            scrollTerminalToBottom();
        } catch (e) {
            console.error('调整终端大小失败:', e);
        }
    }
}, 100);

