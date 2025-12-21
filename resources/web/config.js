// Global state
let providers = [];
let authStatus = {};
let currentTab = 'credentials';
const API_BASE = window.location.origin;

// DOM Elements
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');
const credentialsContainer = document.getElementById('credentials-container');
const proxyContainer = document.getElementById('proxy-container');
const jsonEditor = document.getElementById('json-editor');
const importModal = document.getElementById('import-modal');
const importFile = document.getElementById('import-file');
const serviceUrlSpan = document.getElementById('service-url');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    serviceUrlSpan.textContent = window.location.origin;
    loadProviders();
    setupEventListeners();
});

// Tab switching
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const tabId = tab.dataset.tab;
        switchTab(tabId);
    });
});

function switchTab(tabId) {
    // Update active tab
    tabs.forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');

    // Update active content
    tabContents.forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    currentTab = tabId;

    // Load proxy data if switching to proxy tab
    if (tabId === 'proxy') {
        loadProxyForms();
    }

     // Load EPG mappings if switching to that tab
    if (tabId === 'epg-mapping' && window.epgMappingManager) {
        window.epgMappingManager.loadProviders();
    }
}

// Load providers from API
async function loadProviders() {
    try {
        const response = await fetch(`${API_BASE}/api/providers`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        providers = data.providers;

        // Load auth status for each provider
        await loadAuthStatus();

        renderCredentialsForms();

    } catch (error) {
        credentialsContainer.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <div>
                    <strong>Failed to load providers</strong>
                    <p>${error.message}</p>
                    <p>Make sure the Ultimate Backend service is running.</p>
                </div>
            </div>
        `;
        console.error('Error loading providers:', error);
    }
}

// Load authentication status for all providers
async function loadAuthStatus() {
    for (const provider of providers) {
        try {
            const response = await fetch(`${API_BASE}/api/providers/${provider.name}/auth/status`);
            if (response.ok) {
                authStatus[provider.name] = await response.json();
            }
        } catch (error) {
            console.warn(`Failed to load auth status for ${provider.name}:`, error);
        }
    }
}

// Render credentials forms
// Render credentials forms
async function renderCredentialsForms() {
    if (providers.length === 0) {
        credentialsContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-tv"></i>
                <p>No providers configured</p>
                <p>Check your provider configuration files</p>
            </div>
        `;
        return;
    }

    // Load credentials for all providers in parallel
    const credentialsPromises = providers.map(async (provider) => {
        try {
            // Try to fetch existing credentials
            const credsResponse = await fetch(`${API_BASE}/api/providers/${provider.name}/credentials`);
            let existingCreds = null;

            if (credsResponse.ok) {
                const credsData = await credsResponse.json();
                if (credsData.has_credentials) {
                    existingCreds = credsData;
                }
            }

            // Get auth information from provider
            const auth = provider.auth || {};
            const supportedAuthTypes = auth.supported_auth_types || [];

            // Determine UI based on auth properties
            const needsUserCredentials = auth.needs_user_credentials || false;
            const needsClientCredentials = auth.needs_client_credentials || false;
            const isAnonymous = auth.is_anonymous || false;
            const isNetworkBased = auth.is_network_based || false;
            const usesEmbeddedClient = auth.uses_embedded_client || false;
            const usesDeviceRegistration = auth.uses_device_registration || false;

            // Get current auth status
            const status = authStatus[provider.name] || {};

            // Determine provider card class
            let providerCardClass = 'provider-card';
            if (!needsUserCredentials) {
                providerCardClass += ' client-credentials-only';
            }

            // Create form content based on auth type
            let formContent = '';
            let authDescription = '';

            if (needsUserCredentials) {
                // User credentials form
                formContent = `
                <div class="form-group">
                    <label for="username-${provider.name}">
                        <i class="fas fa-user"></i> Username/Email
                    </label>
                    <input type="text"
                           id="username-${provider.name}"
                           class="form-control"
                           placeholder="user@example.com"
                           value="${existingCreds?.username_masked || ''}"
                           ${existingCreds?.username_masked ? 'readonly style="background-color:#f5f5f5;"' : ''}>
                    ${existingCreds?.username_masked ? `
                    <small style="color:#666; display:block; margin-top:5px;">
                        <i class="fas fa-info-circle"></i> Credentials saved. Enter new values to update.
                    </small>
                    ` : ''}
                </div>

                <div class="form-group">
                    <label for="password-${provider.name}">
                        <i class="fas fa-lock"></i> ${existingCreds ? 'New Password (leave blank to keep current)' : 'Password'}
                    </label>
                    <input type="password"
                           id="password-${provider.name}"
                           class="form-control"
                           placeholder="${existingCreds ? '•••••••• (optional)' : '••••••••'}"
                           value="">
                </div>
                `;
                authDescription = 'Requires username and password';
            } else if (needsClientCredentials && !needsUserCredentials) {
                // Client credentials only (no user input needed)
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-key"></i>
                    <strong>Client Credentials Only</strong>
                    <p>This provider uses hardcoded client credentials that don't require manual setup.</p>
                    <small>Authentication type: ${auth.preferred_auth_type || 'client_credentials'}</small>
                </div>
                `;
                authDescription = 'Uses client credentials';
            } else if (isAnonymous || isNetworkBased || usesEmbeddedClient) {
                // No credentials required
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-check-circle"></i>
                    <strong>No Credentials Required</strong>
                    <p>This provider uses ${auth.preferred_auth_type?.replace('_', ' ') || 'automatic'} authentication.</p>
                    ${supportedAuthTypes.length > 0 ? `
                    <small>Supported auth types: ${supportedAuthTypes.join(', ')}</small>
                    ` : ''}
                </div>
                `;
                authDescription = 'No credentials required';
            } else if (usesDeviceRegistration) {
                // Device registration
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-mobile-alt"></i>
                    <strong>Device Registration</strong>
                    <p>This provider requires device registration. Follow provider-specific setup instructions.</p>
                    <small>Authentication type: ${auth.preferred_auth_type || 'device_registration'}</small>
                </div>
                `;
                authDescription = 'Requires device registration';
            } else {
                // Fallback for unknown auth types
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-question-circle"></i>
                    <strong>Authentication Type Unknown</strong>
                    <p>This provider's authentication method could not be determined.</p>
                    ${supportedAuthTypes.length > 0 ? `
                    <small>Supported auth types: ${supportedAuthTypes.join(', ')}</small>
                    ` : ''}
                </div>
                `;
                authDescription = 'Unknown authentication';
            }

            // Create buttons based on auth type
            let buttonsHTML = '';
            if (needsUserCredentials) {
                buttonsHTML = `
                <div class="btn-group">
                    <button onclick="saveCredentials('${provider.name}')" class="btn btn-primary">
                        <i class="fas fa-save"></i> ${existingCreds ? 'Update' : 'Save'}
                    </button>
                    ${existingCreds ? `
                    <button onclick="deleteCredentials('${provider.name}')" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                    ` : ''}
                    <button onclick="testAuth('${provider.name}')" class="btn btn-success">
                        <i class="fas fa-check"></i> Test
                    </button>
                </div>
                `;
            } else {
                // For non-user-credential providers, only show test button
                buttonsHTML = `
                <div class="btn-group">
                    <button onclick="testAuth('${provider.name}')" class="btn btn-success">
                        <i class="fas fa-check"></i> Test Connection
                    </button>
                </div>
                `;
            }

            return `
            <div class="${providerCardClass}" data-provider="${provider.name}">
                <div class="provider-header">
                    ${provider.logo ? `<img src="${provider.logo}" alt="${provider.label}" class="provider-logo">` : ''}
                    <div class="provider-info">
                        <h3>${provider.label}</h3>
                        <div class="provider-id">${provider.name} • ${provider.country}</div>
                        <div class="auth-info">
                            <small><i class="fas fa-fingerprint"></i> ${authDescription}</small>
                        </div>
                        <div id="status-${provider.name}" class="status-indicator">
                            ${getStatusIcon(status)}
                            ${getStatusText(status)}
                        </div>
                    </div>
                </div>

                ${formContent}
                ${buttonsHTML}
            </div>
            `;
        } catch (error) {
            console.error(`Error loading credentials for ${provider.name}:`, error);
            return ''; // Return empty string on error
        }
    });

    // Wait for all promises and render
    const htmls = await Promise.all(credentialsPromises);
    credentialsContainer.innerHTML = htmls.join('');
}

// Load proxy forms
async function loadProxyForms() {
    proxyContainer.innerHTML = await Promise.all(providers.map(async (provider) => {
        try {
            // Try to load existing proxy config
            const proxyResponse = await fetch(`${API_BASE}/api/providers/${provider.name}/proxy`);
            let existingProxy = null;

            if (proxyResponse.ok) {
                const proxyData = await proxyResponse.json();
                if (proxyData.proxy_config) {
                    existingProxy = proxyData.proxy_config;
                }
            }

            return `
            <div class="provider-card" data-provider="${provider.name}">
                <div class="provider-header">
                    ${provider.logo ? `<img src="${provider.logo}" alt="${provider.label}" class="provider-logo">` : ''}
                    <div class="provider-info">
                        <h3>${provider.label}</h3>
                        <div class="provider-id">Proxy Configuration</div>
                    </div>
                </div>

                <div class="form-group">
                    <label for="proxy-host-${provider.name}">
                        <i class="fas fa-server"></i> Proxy Host
                    </label>
                    <input type="text"
                           id="proxy-host-${provider.name}"
                           class="form-control"
                           placeholder="proxy.example.com"
                           value="${existingProxy?.host || ''}">
                </div>

                <div class="form-group">
                    <label for="proxy-port-${provider.name}">
                        <i class="fas fa-plug"></i> Proxy Port
                    </label>
                    <input type="number"
                           id="proxy-port-${provider.name}"
                           class="form-control"
                           placeholder="8080"
                           min="1"
                           max="65535"
                           value="${existingProxy?.port || ''}">
                </div>

                <div class="form-group">
                    <label for="proxy-type-${provider.name}">
                        <i class="fas fa-network-wired"></i> Proxy Type
                    </label>
                    <select id="proxy-type-${provider.name}" class="form-control">
                        <option value="http" ${(!existingProxy || existingProxy.proxy_type === 'http') ? 'selected' : ''}>HTTP</option>
                        <option value="https" ${(existingProxy?.proxy_type === 'https') ? 'selected' : ''}>HTTPS</option>
                        <option value="socks4" ${(existingProxy?.proxy_type === 'socks4') ? 'selected' : ''}>SOCKS4</option>
                        <option value="socks5" ${(existingProxy?.proxy_type === 'socks5') ? 'selected' : ''}>SOCKS5</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="proxy-user-${provider.name}">
                        <i class="fas fa-user"></i> Username (Optional)
                    </label>
                    <input type="text"
                           id="proxy-user-${provider.name}"
                           class="form-control"
                           placeholder="proxyuser"
                           value="${existingProxy?.auth?.username || ''}">
                </div>

                <div class="form-group">
                    <label for="proxy-pass-${provider.name}">
                        <i class="fas fa-lock"></i> Password (Optional)
                    </label>
                    <input type="password"
                           id="proxy-pass-${provider.name}"
                           class="form-control"
                           placeholder="••••••••"
                           value="${existingProxy?.auth?.password || ''}">
                </div>

                <div class="btn-group">
                    <button onclick="saveProxy('${provider.name}')" class="btn btn-primary">
                        <i class="fas fa-save"></i> ${existingProxy ? 'Update' : 'Save'} Proxy
                    </button>
                    ${existingProxy ? `
                    <button onclick="deleteProxy('${provider.name}')" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Delete Proxy
                    </button>
                    ` : ''}
                </div>
            </div>
            `;
        } catch (error) {
            console.error(`Error loading proxy for ${provider.name}:`, error);
            return ''; // Return empty string on error
        }
    })).then(htmls => htmls.join(''));
}

// Helper functions
function getStatusIcon(status) {
    if (!status) return '<i class="fas fa-question-circle"></i>';

    switch (status.auth_state) {
        case 'AUTHENTICATED':
        case 'user_authenticated':
        case 'client_authenticated':
            return '<i class="fas fa-check-circle"></i>';
        case 'EXPIRED':
        case 'credentials_only':
            return '<i class="fas fa-exclamation-triangle"></i>';
        case 'NOT_AUTHENTICATED':
            return '<i class="fas fa-times-circle"></i>';
        case 'NOT_APPLICABLE':
            return '<i class="fas fa-info-circle"></i>';
        default:
            return '<i class="fas fa-question-circle"></i>';
    }
}

function getStatusText(status) {
    if (!status) return 'Unknown';

    // Map Python AuthState values to readable text
    switch (status.auth_state) {
        case 'AUTHENTICATED':
            return 'Authenticated';
        case 'EXPIRED':
            return 'Token Expired (can refresh)';
        case 'NOT_AUTHENTICATED':
            return 'Not Authenticated';
        case 'NOT_APPLICABLE':
            return 'No Auth Required';
        case 'user_authenticated': // Keep old values for backward compatibility
            return 'User Authenticated';
        case 'client_authenticated':
            return 'Client Authenticated';
        case 'credentials_only':
            return 'Credentials Saved';
        default:
            return status.auth_state || 'Unknown';
    }
}

// API Functions
async function saveCredentials(providerName) {
    // Find the provider from the global providers array
    const provider = providers.find(p => p.name === providerName);
    if (!provider) {
        showAlert('error', `Provider ${providerName} not found`);
        return;
    }

    // Check auth properties
    const auth = provider.auth || {};

    // Check if provider actually needs user credentials
    if (!auth.needs_user_credentials) {
        const authType = auth.preferred_auth_type || 'unknown';
        const authTypeName = authType.replace('_', ' ');

        if (auth.needs_client_credentials && !auth.needs_user_credentials) {
            showAlert('info', `${provider.label} uses client credentials - credentials are hardcoded in the application`);
        } else if (auth.is_anonymous) {
            showAlert('info', `${provider.label} is an anonymous provider - no credentials needed`);
        } else if (auth.is_network_based) {
            showAlert('info', `${provider.label} uses network-based authentication - no manual setup needed`);
        } else if (auth.uses_embedded_client) {
            showAlert('info', `${provider.label} uses embedded client credentials - no manual setup needed`);
        } else if (auth.uses_device_registration) {
            showAlert('info', `${provider.label} requires device registration - follow provider setup instructions`);
        } else {
            showAlert('info', `${provider.label} uses ${authTypeName} authentication - no manual credential setup`);
        }
        return;
    }

    const usernameInput = document.getElementById(`username-${providerName}`);
    const passwordInput = document.getElementById(`password-${providerName}`);

    const username = usernameInput.value;
    const password = passwordInput.value;

    // For updates, username might be readonly with masked value
    // We need to check if user entered a new username
    const isMaskedUsername = usernameInput.hasAttribute('readonly');

    if (isMaskedUsername && !password) {
        // User is keeping existing credentials, no changes
        showAlert('info', 'No changes made to credentials');
        return;
    }

    if (!isMaskedUsername && (!username || !password)) {
        showAlert('error', 'Please enter both username and password for new credentials');
        return;
    }

    // Prepare credentials data
    const credentials = {};

    // Only include username if it's not masked/readonly (new or changed)
    if (!isMaskedUsername && username) {
        credentials.username = username;
    }

    // Only include password if provided (for updates, password can be empty)
    if (password) {
        credentials.password = password;
    }

    const statusEl = document.getElementById(`status-${providerName}`);
    if (statusEl) {
        statusEl.innerHTML = '<span class="loader"></span> Saving...';
    }

    try {
        const response = await fetch(`${API_BASE}/api/providers/${providerName}/credentials`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
        });

        const result = await response.json();

        if (response.ok) {
            if (statusEl) {
                statusEl.className = 'status-indicator status-success';
                statusEl.innerHTML = '<i class="fas fa-check-circle"></i> Saved successfully';
            }

            // Clear password field for security
            passwordInput.value = '';

            // If username was changed, mark it as readonly with masked value
            if (!isMaskedUsername && username) {
                // Create a masked version for display
                let maskedUsername;
                if (username.includes('@')) {
                    const parts = username.split('@');
                    maskedUsername = parts[0].substring(0, 2) + '***@' + parts[1];
                } else {
                    maskedUsername = username.substring(0, 2) + '***';
                }

                usernameInput.value = maskedUsername;
                usernameInput.readOnly = true;
                usernameInput.style.backgroundColor = '#f5f5f5';

                // Add info text
                const infoText = document.createElement('small');
                infoText.innerHTML = '<i class="fas fa-info-circle"></i> Credentials saved. Enter new values to update.';
                infoText.style.cssText = 'color:#666; display:block; margin-top:5px;';

                // Remove existing info if any
                const existingInfo = usernameInput.nextElementSibling;
                if (existingInfo && existingInfo.tagName === 'SMALL') {
                    existingInfo.remove();
                }

                usernameInput.parentNode.insertBefore(infoText, passwordInput);
            }

            // Reload auth status
            await loadAuthStatus();

            // Show success message
            const action = isMaskedUsername && !username ? 'Updated' : 'Saved';
            showAlert('success', `${action} credentials for ${provider.label}`);
        } else {
            if (statusEl) {
                statusEl.className = 'status-indicator status-error';
                statusEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${result.error || 'Failed to save'}`;
            }
            showAlert('error', result.error || `Failed to save credentials for ${provider.label}`);
        }
    } catch (error) {
        if (statusEl) {
            statusEl.className = 'status-indicator status-error';
            statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Network error';
        }
        showAlert('error', `Network error: ${error.message}`);
        console.error('Save error:', error);
    }
}

async function deleteCredentials(providerName) {
    // Find the provider from the global providers array
    const provider = providers.find(p => p.name === providerName);
    if (!provider) {
        showAlert('error', `Provider ${providerName} not found`);
        return;
    }

    // Check auth properties
    const auth = provider.auth || {};

    // Check if provider actually uses user credentials
    if (!auth.needs_user_credentials) {
        const authType = auth.preferred_auth_type || 'unknown';
        const authTypeName = authType.replace('_', ' ');

        if (auth.needs_client_credentials && !auth.needs_user_credentials) {
            showAlert('info', `${provider.label} uses hardcoded client credentials - nothing to delete`);
        } else if (auth.is_anonymous) {
            showAlert('info', `${provider.label} is an anonymous provider - no credentials to delete`);
        } else if (auth.is_network_based) {
            showAlert('info', `${provider.label} uses network-based authentication - no credentials stored`);
        } else if (auth.uses_embedded_client) {
            showAlert('info', `${provider.label} uses embedded client credentials - nothing to delete`);
        } else if (auth.uses_device_registration) {
            showAlert('info', `${provider.label} uses device registration - no stored credentials to delete`);
        } else {
            showAlert('info', `${provider.label} uses ${authTypeName} authentication - no credentials to delete`);
        }
        return;
    }

    if (!confirm(`Delete credentials for ${providerName}?`)) return;

    const statusEl = document.getElementById(`status-${providerName}`);
    if (statusEl) {
        statusEl.innerHTML = '<span class="loader"></span> Deleting...';
    }

    try {
        const response = await fetch(`${API_BASE}/api/providers/${providerName}/credentials`, {
            method: 'DELETE'
        });

        if (response.ok) {
            if (statusEl) {
                statusEl.className = 'status-indicator status-warning';
                statusEl.innerHTML = '<i class="fas fa-info-circle"></i> Credentials deleted';
            }

            // Clear fields if they exist
            const usernameInput = document.getElementById(`username-${providerName}`);
            const passwordInput = document.getElementById(`password-${providerName}`);

            if (usernameInput) usernameInput.value = '';
            if (passwordInput) passwordInput.value = '';

            // Reload auth status
            await loadAuthStatus();
            renderCredentialsForms();

            showAlert('success', `Credentials deleted for ${providerName}`);
        } else {
            const result = await response.json();
            if (statusEl) {
                statusEl.className = 'status-indicator status-error';
                statusEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${result.error || 'Delete failed'}`;
            }
            showAlert('error', result.error || `Failed to delete credentials for ${providerName}`);
        }
    } catch (error) {
        if (statusEl) {
            statusEl.className = 'status-indicator status-error';
            statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Network error';
        }
        showAlert('error', `Network error: ${error.message}`);
        console.error('Delete error:', error);
    }
}

async function testAuth(providerName) {
    const statusEl = document.getElementById(`status-${providerName}`);
    statusEl.innerHTML = '<span class="loader"></span> Testing...';

    try {
        const response = await fetch(`${API_BASE}/api/providers/${providerName}/auth/status`);
        const result = await response.json();

        if (response.ok) {
            if (result.is_ready) {
                statusEl.className = 'status-indicator status-success';
                statusEl.innerHTML = '<i class="fas fa-check-circle"></i> Ready to use';
                showAlert('success', `${providerName} is ready to use`);
            } else {
                statusEl.className = 'status-indicator status-warning';
                statusEl.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${result.auth_state}`;
                showAlert('warning', `${providerName} status: ${result.auth_state}`);
            }
        } else {
            statusEl.className = 'status-indicator status-error';
            statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Test failed';
            showAlert('error', `Test failed for ${providerName}`);
        }
    } catch (error) {
        statusEl.className = 'status-indicator status-error';
        statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Network error';
        showAlert('error', `Network error: ${error.message}`);
        console.error('Test error:', error);
    }
}

async function saveProxy(providerName) {
    const host = document.getElementById(`proxy-host-${providerName}`).value;
    const port = document.getElementById(`proxy-port-${providerName}`).value;
    const type = document.getElementById(`proxy-type-${providerName}`).value;
    const user = document.getElementById(`proxy-user-${providerName}`).value;
    const pass = document.getElementById(`proxy-pass-${providerName}`).value;

    if (!host || !port) {
        showAlert('error', 'Please fill in at least Host and Port fields');
        return;
    }

    const proxyConfig = {
        host,
        port: parseInt(port),
        proxy_type: type
    };

    if (user) proxyConfig.username = user;
    if (pass) proxyConfig.password = pass;

    try {
        const response = await fetch(`${API_BASE}/api/providers/${providerName}/proxy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(proxyConfig)
        });

        if (response.ok) {
            showAlert('success', `Proxy configuration saved for ${providerName}`);
            // Clear password field
            document.getElementById(`proxy-pass-${providerName}`).value = '';
        } else {
            const result = await response.json();
            showAlert('error', result.error || `Failed to save proxy for ${providerName}`);
        }
    } catch (error) {
        showAlert('error', `Network error: ${error.message}`);
        console.error('Proxy save error:', error);
    }
}

async function deleteProxy(providerName) {
    if (!confirm(`Delete proxy configuration for ${providerName}?`)) return;

    try {
        const response = await fetch(`${API_BASE}/api/providers/${providerName}/proxy`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showAlert('success', `Proxy configuration deleted for ${providerName}`);
            // Clear fields
            document.getElementById(`proxy-host-${providerName}`).value = '';
            document.getElementById(`proxy-port-${providerName}`).value = '';
            document.getElementById(`proxy-user-${providerName}`).value = '';
            document.getElementById(`proxy-pass-${providerName}`).value = '';
        } else {
            const result = await response.json();
            showAlert('error', result.error || `Failed to delete proxy for ${providerName}`);
        }
    } catch (error) {
        showAlert('error', `Network error: ${error.message}`);
        console.error('Proxy delete error:', error);
    }
}

// UI Helper Functions
function showAlert(type, message) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <div>${message}</div>
    `;

    // Insert at beginning of card body
    const cardBody = document.querySelector('.card-body');
    cardBody.insertBefore(alert, cardBody.firstChild);

    // Remove after 5 seconds
    setTimeout(() => alert.remove(), 5000);
}

function setupEventListeners() {
    // Export button
    document.getElementById('btn-export').addEventListener('click', exportConfig);
    document.getElementById('btn-export-json').addEventListener('click', exportConfig);

    // Import button
    document.getElementById('btn-import').addEventListener('click', () => importModal.style.display = 'flex');
    document.getElementById('btn-import-json').addEventListener('click', () => importModal.style.display = 'flex');

    // Import modal
    document.getElementById('btn-cancel-import').addEventListener('click', () => importModal.style.display = 'none');
    document.getElementById('btn-confirm-import').addEventListener('click', importConfig);

    // Apply JSON config
    document.getElementById('btn-apply-json').addEventListener('click', applyJsonConfig);

    // Test connection
    document.getElementById('btn-test-connection').addEventListener('click', testApiConnection);

    // Clear all
    document.getElementById('btn-clear-all').addEventListener('click', clearAllConfigurations);
}

async function exportConfig() {
    try {
        const response = await fetch(`${API_BASE}/api/config/export`);
        if (!response.ok) throw new Error('Export failed');

        const data = await response.json();

        // Create download link
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ultimate_backend_config_${new Date().toISOString().slice(0,10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showAlert('success', 'Configuration exported successfully');
    } catch (error) {
        showAlert('error', `Export failed: ${error.message}`);
    }
}

async function importConfig() {
    const file = importFile.files[0];
    if (!file) {
        showAlert('error', 'Please select a file first');
        return;
    }

    try {
        const text = await file.text();
        const config = JSON.parse(text);

        const response = await fetch(`${API_BASE}/api/config/import`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (response.ok) {
            showAlert('success', 'Configuration imported successfully');
            importModal.style.display = 'none';
            importFile.value = '';

            // Reload providers
            await loadProviders();
            loadProxyForms();
        } else {
            const result = await response.json();
            showAlert('error', result.error || 'Import failed');
        }
    } catch (error) {
        showAlert('error', `Import failed: ${error.message}`);
    }
}

async function applyJsonConfig() {
    const jsonText = jsonEditor.value.trim();
    if (!jsonText) {
        showAlert('error', 'Please enter JSON configuration');
        return;
    }

    try {
        const config = JSON.parse(jsonText);

        const response = await fetch(`${API_BASE}/api/config/import`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (response.ok) {
            showAlert('success', 'Configuration applied successfully');
            jsonEditor.value = '';

            // Reload providers
            await loadProviders();
            loadProxyForms();
        } else {
            const result = await response.json();
            showAlert('error', result.error || 'Failed to apply configuration');
        }
    } catch (error) {
        showAlert('error', `Invalid JSON: ${error.message}`);
    }
}

async function testApiConnection() {
    try {
        const response = await fetch(`${API_BASE}/api/providers`);
        if (response.ok) {
            showAlert('success', 'API connection successful');
        } else {
            showAlert('error', `API returned ${response.status}`);
        }
    } catch (error) {
        showAlert('error', `API connection failed: ${error.message}`);
    }
}

async function clearAllConfigurations() {
    if (!confirm('Are you sure you want to clear ALL configurations? This cannot be undone.')) {
        return;
    }

    if (!confirm('This will delete all credentials and proxy settings. Are you REALLY sure?')) {
        return;
    }

    try {
        // Get all providers first
        const response = await fetch(`${API_BASE}/api/providers`);
        const data = await response.json();

        // Delete credentials for all providers
        for (const provider of data.providers) {
            // Skip client-only providers
            if (provider.requires_user_credentials) {
                await fetch(`${API_BASE}/api/providers/${provider.name}/credentials`, {
                    method: 'DELETE'
                });
            }

            await fetch(`${API_BASE}/api/providers/${provider.name}/proxy`, {
                method: 'DELETE'
            });
        }

        showAlert('success', 'All configurations cleared');

        // Reload providers
        await loadProviders();
        loadProxyForms();
    } catch (error) {
        showAlert('error', `Failed to clear configurations: ${error.message}`);
    }
}

// Make functions available globally
window.saveCredentials = saveCredentials;
window.deleteCredentials = deleteCredentials;
window.testAuth = testAuth;
window.saveProxy = saveProxy;
window.deleteProxy = deleteProxy;