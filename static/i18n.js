/**
 * Internationalization (i18n) Module
 * Supports Chinese (zh-CN) and English (en-US)
 * Author: steven
 */

const translations = {
    'zh-CN': {
        // Common
        'app.title': 'Web SSH 客户端',
        'app.login.title': '登录 - Web SSH',
        'common.confirm': '确认',
        'common.cancel': '取消',
        'common.save': '保存',
        'common.delete': '删除',
        'common.edit': '编辑',
        'common.close': '关闭',
        'common.submit': '提交',
        'common.loading': '加载中...',
        'common.success': '成功',
        'common.error': '错误',
        'common.warning': '警告',
        
        // Login Page
        'login.title': '登录',
        'login.username': '用户名',
        'login.password': '密码',
        'login.totp': '验证码（如已启用 2FA）',
        'login.button': '登录',
        'login.success': '登录成功！',
        'login.error': '登录失败',
        'login.username.placeholder': '请输入用户名',
        'login.password.placeholder': '请输入密码',
        'login.totp.placeholder': '6位验证码',
        
        // Header
        'header.logout': '退出',
        'header.change.password': '修改密码',
        'header.audit.log': '审计日志',
        'header.2fa': '2FA',
        'header.language': '语言',
        
        // SSH Connection
        'ssh.saved.connections': '已保存的连接',
        'ssh.new.connection': '新建连接',
        'ssh.no.connections': '暂无保存的连接',
        'ssh.host': '主机地址',
        'ssh.port': '端口',
        'ssh.username': '用户名',
        'ssh.password': '密码',
        'ssh.auth.type': '认证方式',
        'ssh.auth.password': '密码认证',
        'ssh.auth.key': '密钥认证',
        'ssh.private.key': '私钥',
        'ssh.config.name': '配置名称',
        'ssh.connect': '连接',
        'ssh.disconnect': '断开连接',
        'ssh.save.config': '保存配置',
        'ssh.cancel': '取消',
        'ssh.connecting': '连接中...',
        'ssh.connected': '已连接',
        'ssh.disconnected': '已断开',
        'ssh.connection.failed': 'SSH 连接失败',
        'ssh.host.placeholder': '例如: 192.168.1.100',
        'ssh.username.placeholder': '例如: root',
        'ssh.password.placeholder': '请输入密码',
        'ssh.config.name.placeholder': '例如: 生产服务器',
        'ssh.delete.confirm': '确定要删除这个配置吗？',
        'ssh.last.used': '最后使用',
        'ssh.never.used': '从未使用',
        'ssh.saved.connections': '已保存的连接',
        'ssh.no.saved.connections': '暂无保存的连接',
        'ssh.new.connection': '新建连接',
        
        // Change Password
        'password.change.title': '修改密码',
        'password.old': '当前密码',
        'password.new': '新密码',
        'password.confirm': '确认新密码',
        'password.old.placeholder': '请输入当前密码',
        'password.new.placeholder': '请输入新密码（至少6位）',
        'password.confirm.placeholder': '请再次输入新密码',
        'password.change.button': '修改密码',
        'password.change.success': '密码修改成功！请重新登录',
        'password.change.error': '密码修改失败',
        'password.mismatch': '两次输入的密码不一致',
        'password.too.short': '密码长度至少为6位',
        'password.same.as.old': '新密码不能与当前密码相同',
        
        // 2FA / TOTP
        'totp.title': '双因素认证 (2FA)',
        'totp.status': '2FA 状态',
        'totp.enabled': '已启用',
        'totp.disabled': '未启用',
        'totp.enable': '启用 2FA',
        'totp.disable': '禁用 2FA',
        'totp.setup.title': '设置 2FA',
        'totp.scan.qr': '扫描二维码',
        'totp.scan.instruction': '使用 Google Authenticator 或其他认证器应用扫描此二维码',
        'totp.manual.entry': '手动输入',
        'totp.verify.code': '验证码',
        'totp.verify.code.placeholder': '请输入6位验证码',
        'totp.verify.button': '验证并启用',
        'totp.enable.success': '2FA 启用成功！',
        'totp.enable.error': '2FA 启用失败',
        'totp.disable.title': '禁用 2FA',
        'totp.disable.password': '请输入密码以确认',
        'totp.disable.code': '请输入当前验证码',
        'totp.disable.button': '禁用 2FA',
        'totp.disable.success': '2FA 已禁用',
        'totp.disable.error': '禁用失败',
        'totp.password.placeholder': '请输入密码',
        'totp.code.placeholder': '请输入验证码',
        'totp.status.error': '获取 2FA 状态失败',
        'totp.setup.error': '设置 2FA 失败',
        
        // Audit Log
        'audit.title': '审计日志',
        'audit.time': '时间',
        'audit.user': '用户',
        'audit.action': '操作',
        'audit.target': '目标',
        'audit.details': '详情',
        'audit.status': '状态',
        'audit.success': '成功',
        'audit.failed': '失败',
        'audit.no.logs': '暂无日志',
        'audit.load.error': '加载日志失败',
        
        // Actions
        'action.Login': '登录',
        'action.Logout': '登出',
        'action.SshConnect': 'SSH连接',
        'action.SshDisconnect': 'SSH断开',
        'action.SshCommand': 'SSH命令',
        'action.CreateConfig': '创建配置',
        'action.UpdateConfig': '更新配置',
        'action.DeleteConfig': '删除配置',
        'action.CreateUser': '创建用户',
        'action.DeleteUser': '删除用户',
        'action.ChangePassword': '修改密码',
        'action.EnableTotp': '启用2FA',
        'action.DisableTotp': '禁用2FA',
        
        // Error Messages
        'error.network': '网络错误',
        'error.unauthorized': '未授权，请重新登录',
        'error.forbidden': '权限不足',
        'error.not.found': '资源不存在',
        'error.server': '服务器错误',
        'error.unknown': '未知错误',

        // SSH Config
        'config.load.error': '加载配置失败',
        'config.delete.error': '删除失败',
        'config.save.error': '保存失败',
        'config.delete.confirm': '确定要删除这个配置吗？',

        // Form validation
        'form.password.required': '请输入密码',
        'form.key.required': '请输入或选择私钥文件',
        'form.config.name.required': '请输入连接名称',

        // Common
        'common.or': '或者',
        'common.refresh': '刷新',
        'audit.limit': '显示数量',
    },
    
    'en-US': {
        // Common
        'app.title': 'Web SSH Client',
        'app.login.title': 'Login - Web SSH',
        'common.confirm': 'Confirm',
        'common.cancel': 'Cancel',
        'common.save': 'Save',
        'common.delete': 'Delete',
        'common.edit': 'Edit',
        'common.close': 'Close',
        'common.submit': 'Submit',
        'common.loading': 'Loading...',
        'common.success': 'Success',
        'common.error': 'Error',
        'common.warning': 'Warning',
        
        // Login Page
        'login.title': 'Login',
        'login.username': 'Username',
        'login.password': 'Password',
        'login.totp': 'TOTP Code (if 2FA enabled)',
        'login.button': 'Login',
        'login.success': 'Login successful!',
        'login.error': 'Login failed',
        'login.username.placeholder': 'Enter username',
        'login.password.placeholder': 'Enter password',
        'login.totp.placeholder': '6-digit code',
        
        // Header
        'header.logout': 'Logout',
        'header.change.password': 'Change PW',
        'header.audit.log': 'Audit Log',
        'header.2fa': '2FA',
        'header.language': 'Language',
        
        // SSH Connection
        'ssh.saved.connections': 'Saved Connections',
        'ssh.new.connection': 'New Connection',
        'ssh.no.connections': 'No saved connections',
        'ssh.host': 'Host',
        'ssh.port': 'Port',
        'ssh.username': 'Username',
        'ssh.password': 'Password',
        'ssh.auth.type': 'Auth Type',
        'ssh.auth.password': 'Password',
        'ssh.auth.key': 'Private Key',
        'ssh.private.key': 'Private Key',
        'ssh.config.name': 'Config Name',
        'ssh.connect': 'Connect',
        'ssh.disconnect': 'Disconnect',
        'ssh.save.config': 'Save Config',
        'ssh.cancel': 'Cancel',
        'ssh.connecting': 'Connecting...',
        'ssh.connected': 'Connected',
        'ssh.disconnected': 'Disconnected',
        'ssh.connection.failed': 'SSH connection failed',
        'ssh.host.placeholder': 'e.g., 192.168.1.100',
        'ssh.username.placeholder': 'e.g., root',
        'ssh.password.placeholder': 'Enter password',
        'ssh.config.name.placeholder': 'e.g., Production Server',
        'ssh.delete.confirm': 'Are you sure you want to delete this config?',
        'ssh.last.used': 'Last used',
        'ssh.never.used': 'Never used',
        'ssh.saved.connections': 'Saved Connections',
        'ssh.no.saved.connections': 'No saved connections',
        'ssh.new.connection': 'New Connection',
        
        // Change Password
        'password.change.title': 'Change Password',
        'password.old': 'Current Password',
        'password.new': 'New Password',
        'password.confirm': 'Confirm Password',
        'password.old.placeholder': 'Enter current password',
        'password.new.placeholder': 'Enter new password (min 6 chars)',
        'password.confirm.placeholder': 'Re-enter new password',
        'password.change.button': 'Change Password',
        'password.change.success': 'Password changed successfully! Please login again',
        'password.change.error': 'Failed to change password',
        'password.mismatch': 'Passwords do not match',
        'password.too.short': 'Password must be at least 6 characters',
        'password.same.as.old': 'New password cannot be the same as current password',
        
        // 2FA / TOTP
        'totp.title': 'Two-Factor Authentication (2FA)',
        'totp.status': '2FA Status',
        'totp.enabled': 'Enabled',
        'totp.disabled': 'Disabled',
        'totp.enable': 'Enable 2FA',
        'totp.disable': 'Disable 2FA',
        'totp.setup.title': 'Setup 2FA',
        'totp.scan.qr': 'Scan QR Code',
        'totp.scan.instruction': 'Scan this QR code with Google Authenticator or other authenticator app',
        'totp.manual.entry': 'Manual Entry',
        'totp.verify.code': 'Verification Code',
        'totp.verify.code.placeholder': 'Enter 6-digit code',
        'totp.verify.button': 'Verify and Enable',
        'totp.enable.success': '2FA enabled successfully!',
        'totp.enable.error': 'Failed to enable 2FA',
        'totp.disable.title': 'Disable 2FA',
        'totp.disable.password': 'Enter password to confirm',
        'totp.disable.code': 'Enter current verification code',
        'totp.disable.button': 'Disable 2FA',
        'totp.disable.success': '2FA disabled',
        'totp.disable.error': 'Failed to disable 2FA',
        'totp.password.placeholder': 'Enter password',
        'totp.code.placeholder': 'Enter verification code',
        'totp.status.error': 'Failed to get 2FA status',
        'totp.setup.error': 'Failed to setup 2FA',
        
        // Audit Log
        'audit.title': 'Audit Log',
        'audit.time': 'Time',
        'audit.user': 'User',
        'audit.action': 'Action',
        'audit.target': 'Target',
        'audit.details': 'Details',
        'audit.status': 'Status',
        'audit.success': 'Success',
        'audit.failed': 'Failed',
        'audit.no.logs': 'No logs',
        'audit.load.error': 'Failed to load logs',
        
        // Actions
        'action.Login': 'Login',
        'action.Logout': 'Logout',
        'action.SshConnect': 'SSH Connect',
        'action.SshDisconnect': 'SSH Disconnect',
        'action.SshCommand': 'SSH Command',
        'action.CreateConfig': 'Create Config',
        'action.UpdateConfig': 'Update Config',
        'action.DeleteConfig': 'Delete Config',
        'action.CreateUser': 'Create User',
        'action.DeleteUser': 'Delete User',
        'action.ChangePassword': 'Change Password',
        'action.EnableTotp': 'Enable 2FA',
        'action.DisableTotp': 'Disable 2FA',
        
        // Error Messages
        'error.network': 'Network error',
        'error.unauthorized': 'Unauthorized, please login again',
        'error.forbidden': 'Permission denied',
        'error.not.found': 'Resource not found',
        'error.server': 'Server error',
        'error.unknown': 'Unknown error',

        // SSH Config
        'config.load.error': 'Failed to load config',
        'config.delete.error': 'Failed to delete',
        'config.save.error': 'Failed to save',
        'config.delete.confirm': 'Are you sure you want to delete this config?',

        // Form validation
        'form.password.required': 'Please enter password',
        'form.key.required': 'Please enter or select private key file',
        'form.config.name.required': 'Please enter connection name',

        // Common
        'common.or': 'Or',
        'common.refresh': 'Refresh',
        'audit.limit': 'Limit',
    }
};

class I18n {
    constructor() {
        // Get language from localStorage or browser, default to Chinese
        this.currentLang = localStorage.getItem('language') || 
                          (navigator.language.startsWith('zh') ? 'zh-CN' : 'en-US');
        this.translations = translations;
    }
    
    /**
     * Get translation for a key
     * @param {string} key - Translation key
     * @param {object} params - Optional parameters for interpolation
     * @returns {string} Translated text
     */
    t(key, params = {}) {
        let text = this.translations[this.currentLang][key] || key;
        
        // Simple parameter interpolation
        Object.keys(params).forEach(param => {
            text = text.replace(`{${param}}`, params[param]);
        });
        
        return text;
    }
    
    /**
     * Set current language
     * @param {string} lang - Language code ('zh-CN' or 'en-US')
     */
    setLanguage(lang) {
        if (this.translations[lang]) {
            this.currentLang = lang;
            localStorage.setItem('language', lang);
            this.updatePageLanguage();
        }
    }
    
    /**
     * Get current language
     * @returns {string} Current language code
     */
    getLanguage() {
        return this.currentLang;
    }
    
    /**
     * Update all elements with data-i18n attribute
     */
    updatePageLanguage() {
        // Update elements with data-i18n attribute
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            element.textContent = this.t(key);
        });
        
        // Update elements with data-i18n-placeholder attribute
        document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
            const key = element.getAttribute('data-i18n-placeholder');
            element.placeholder = this.t(key);
        });
        
        // Update page title
        const titleKey = document.body.getAttribute('data-i18n-title');
        if (titleKey) {
            document.title = this.t(titleKey);
        }
        
        // Update html lang attribute
        document.documentElement.lang = this.currentLang;
        
        // Trigger custom event for dynamic content updates
        window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang: this.currentLang } }));
    }
}

// Create global i18n instance
const i18n = new I18n();

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => i18n.updatePageLanguage());
} else {
    i18n.updatePageLanguage();
}

