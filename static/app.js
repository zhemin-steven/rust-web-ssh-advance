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
        alert('新密码和确认密码不匹配！');
        return;
    }

    if (newPassword.length < 6) {
        alert('新密码长度至少为 6 个字符！');
        return;
    }

    if (newPassword === currentPassword) {
        alert('新密码不能与当前密码相同！');
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
            alert('✅ 密码修改成功！请重新登录。');
            localStorage.clear();
            window.location.href = '/login.html';
        } else {
            alert('❌ 密码修改失败: ' + (data.error || '未知错误'));
        }
    } catch (error) {
        console.error('Failed to change password:', error);
        alert('❌ 密码修改失败，请稍后重试');
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
            alert('获取 2FA 状态失败: ' + data.error);
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
            statusText.innerHTML = '✅ <strong>2FA 已启用</strong><br><small style="color: #666;">您的账号已受到双因素认证保护</small>';
            enableBtn.style.display = 'none';
            disableBtn.style.display = 'block';
        } else {
            statusText.innerHTML = '⚠️ <strong>2FA 未启用</strong><br><small style="color: #666;">建议启用双因素认证以提高账号安全性</small>';
            enableBtn.style.display = 'block';
            disableBtn.style.display = 'none';
        }
    } catch (error) {
        console.error('Failed to get TOTP status:', error);
        alert('获取 2FA 状态失败');
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
            alert('设置 2FA 失败: ' + data.error);
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
        alert('设置 2FA 失败');
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
            alert('✅ 2FA 启用成功！下次登录时需要输入验证码。');
            document.getElementById('totp-modal').style.display = 'none';
        } else {
            alert('❌ 启用失败: ' + (data.error || '验证码错误'));
        }
    } catch (error) {
        console.error('Failed to enable TOTP:', error);
        alert('❌ 启用失败，请稍后重试');
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
            alert('✅ 2FA 已禁用');
            document.getElementById('totp-modal').style.display = 'none';
        } else {
            alert('❌ 禁用失败: ' + (data.error || '密码或验证码错误'));
        }
    } catch (error) {
        console.error('Failed to disable TOTP:', error);
        alert('❌ 禁用失败，请稍后重试');
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

    auditLogsContainer.innerHTML = '<p class="loading">加载中...</p>';

    try {
        const response = await fetch(`/api/audit/logs?limit=${limit}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        const data = await response.json();

        if (data.error) {
            auditLogsContainer.innerHTML = `<p class="no-logs">错误: ${data.error}</p>`;
            return;
        }

        if (!Array.isArray(data) || data.length === 0) {
            auditLogsContainer.innerHTML = '<p class="no-logs">暂无审计日志</p>';
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
                        ${log.target ? ` • 目标: ${escapeHtml(log.target)}` : ''}
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

// Get action text in Chinese
function getActionText(action) {
    const actionMap = {
        'Login': '🔐 登录',
        'Logout': '🚪 登出',
        'SshConnect': '🔌 SSH 连接',
        'SshDisconnect': '🔌 SSH 断开',
        'SshCommand': '⌨️ SSH 命令',
        'CreateConfig': '➕ 创建配置',
        'UpdateConfig': '✏️ 更新配置',
        'DeleteConfig': '🗑️ 删除配置',
        'CreateUser': '👤 创建用户',
        'DeleteUser': '👤 删除用户',
    };
    return actionMap[action] || action;
}

// Base64 encoding/decoding utilities
const utf8ToBase64 = (str) => btoa(unescape(encodeURIComponent(str)));
const base64ToUtf8 = (str) => decodeURIComponent(escape(atob(str)));

// Global variables
let terminal = null;
let socket = null;
let fitAddon = null;
let lastSelectionTime = 0;
let savedSelection = '';

// Copy text to clipboard using fallback method
function copyTextFallback(text) {
    try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.top = '0';
        textArea.style.left = '0';
        textArea.style.opacity = '0';
        
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        document.execCommand('copy');
        document.body.removeChild(textArea);
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
            configList.innerHTML = '<p class="no-configs">暂无保存的连接</p>';
            return;
        }

        configList.innerHTML = configs.map(config => `
            <div class="config-item">
                <div class="config-info">
                    <div class="config-name">${escapeHtml(config.name)}</div>
                    <div class="config-details">
                        ${escapeHtml(config.username)}@${escapeHtml(config.host)}:${config.port}
                        ${config.last_used ? ` • 最后使用: ${new Date(config.last_used * 1000).toLocaleString()}` : ''}
                    </div>
                </div>
                <div class="config-actions">
                    <button class="btn-use" onclick="useConfig('${config.id}')">连接</button>
                    <button class="btn-delete" onclick="deleteConfig('${config.id}')">删除</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load configs:', error);
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
            alert('加载配置失败: ' + config.error);
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
        alert('加载配置失败');
    }
}

// Delete a saved configuration
async function deleteConfig(configId) {
    if (!confirm('确定要删除这个配置吗？')) {
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
            alert('删除失败: ' + (result.error || '未知错误'));
        }
    } catch (error) {
        console.error('Failed to delete config:', error);
        alert('删除失败');
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
            alert('保存失败: ' + (result.error || '未知错误'));
            return false;
        }
    } catch (error) {
        console.error('Failed to save config:', error);
        alert('保存失败');
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
            alert('请输入密码');
            return;
        }
    } else {
        privateKey = privateKeyTextarea.value;
        if (!privateKey) {
            alert('请输入或选择私钥文件');
            return;
        }
        password = document.getElementById('passphrase').value;
    }

    // Save configuration if checkbox is checked
    if (saveConfigCheckbox.checked) {
        const configName = configNameInput.value.trim();
        if (!configName) {
            alert('请输入连接名称');
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
    
    if (terminal) {
        terminal.dispose();
        terminal = null;
    }
}

// Show terminal
function showTerminal() {
    connectForm.style.display = 'none';
    terminalContainer.style.display = 'flex';
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
    terminal.open(document.getElementById('terminal'));

    const terminalElement = document.getElementById('terminal');

    // Handle keyboard events
    terminalElement.addEventListener('keydown', (e) => {
        // Ctrl+C / Cmd+C - Copy
        if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'C')) {
            const selection = savedSelection || terminal.getSelection();
            if (selection && selection.length > 0) {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(selection).catch(() => copyTextFallback(selection));
                } else {
                    copyTextFallback(selection);
                }

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
    terminalElement.addEventListener('contextmenu', (e) => {
        setTimeout(() => {
            const selection = terminal.getSelection();
            if (selection && selection.length > 0) {
                copyTextFallback(selection);
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

        setTimeout(() => fitAddon.fit(), 200);

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
            }
        });

        // Handle window resize
        window.addEventListener('resize', handleResize);
        setTimeout(handleResize, 300);
    };

    socket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            
            switch (msg.type) {
                case 'stdout':
                    terminal.write(base64ToUtf8(msg.data));
                    break;
                case 'stderr':
                    terminal.write('\x1b[31m' + base64ToUtf8(msg.data) + '\x1b[0m');
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
        } catch (e) {
            console.error('调整终端大小失败:', e);
        }
    }
}, 100);

