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

// Helper function to format timestamp to local date/time
function formatDateTime(timestamp) {
    if (!timestamp) return null;
    const date = new Date(timestamp * 1000); // Convert Unix timestamp to milliseconds
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${day}.${month}.${year} ${hours}:${minutes}`;
}

// Helper function to format relative time
function formatRelativeTime(seconds) {
    if (!seconds && seconds !== 0) return null;

    const absSeconds = Math.abs(seconds);
    const isPast = seconds < 0;

    if (absSeconds < 60) {
        return isPast ? 'just expired' : 'in less than a minute';
    }

    const minutes = Math.floor(absSeconds / 60);
    if (minutes < 60) {
        const text = minutes === 1 ? '1 minute' : `${minutes} minutes`;
        return isPast ? `${text} ago` : `in ${text}`;
    }

    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
        const text = hours === 1 ? '1 hour' : `${hours} hours`;
        return isPast ? `${text} ago` : `in ${text}`;
    }

    const days = Math.floor(hours / 24);
    const text = days === 1 ? '1 day' : `${days} days`;
    return isPast ? `${text} ago` : `in ${text}`;
}

// Helper function to get authentication type description
function getAuthTypeDescription(status) {
    if (!status || !status.auth_type) {
        return 'Unknown authentication';
    }

    const authType = status.auth_type;

    // Map auth types to readable descriptions
    const authTypeMap = {
        'user_credentials': 'User Credentials authentication',
        'client_credentials': 'Client Credentials authentication',
        'anonymous': 'Anonymous authentication',
        'network_based': 'Network-based authentication',
        'device_registration': 'Device Registration authentication',
        'embedded_client': 'Embedded Client authentication'
    };

    return authTypeMap[authType] || `${authType.replace(/_/g, ' ')} authentication`;
}

// Helper function to format token expiration info
function formatTokenExpiration(status) {
    if (!status) return '';

    let expirationHTML = '';

    // Main token expiration
    if (status.token_expires_at) {
        const formattedDate = formatDateTime(status.token_expires_at);
        const relativeTime = formatRelativeTime(status.token_expires_in_seconds);

        if (status.token_expires_in_seconds < 0) {
            // Expired
            expirationHTML += `
                <div class="token-expiration expired">
                    <i class="fas fa-clock"></i> Token expired ${relativeTime}
                </div>
            `;
        } else {
            // Valid
            expirationHTML += `
                <div class="token-expiration">
                    <i class="fas fa-clock"></i> Token expires: ${formattedDate} (${relativeTime})
                </div>
            `;
        }
    }

    // Refresh token expiration (if available)
    if (status.refresh_token_expires_at) {
        const formattedDate = formatDateTime(status.refresh_token_expires_at);
        const relativeTime = formatRelativeTime(status.refresh_token_expires_in_seconds);

        if (status.refresh_token_expires_in_seconds < 0) {
            // Expired
            expirationHTML += `
                <div class="token-expiration expired">
                    <i class="fas fa-sync-alt"></i> Refresh token expired ${relativeTime}
                </div>
            `;
        } else {
            // Valid
            expirationHTML += `
                <div class="token-expiration">
                    <i class="fas fa-sync-alt"></i> Refresh token expires: ${formattedDate} (${relativeTime})
                </div>
            `;
        }
    }

    return expirationHTML;
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
                           placeholder="${existingCreds ? '••••••••• (optional)' : '•••••••••'}"
                           value="">
                </div>
                `;
            } else if (needsClientCredentials && !needsUserCredentials) {
                // Client credentials only (no user input needed)
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-key"></i>
                    <strong>Client Credentials Only</strong>
                    <p>This provider uses hardcoded client credentials that don't require manual setup.</p>
                </div>
                `;
            } else if (isAnonymous || isNetworkBased || usesEmbeddedClient) {
                // No credentials required
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-check-circle"></i>
                    <strong>No Credentials Required</strong>
                    <p>This provider uses ${auth.preferred_auth_type?.replace('_', ' ') || 'automatic'} authentication.</p>
                </div>
                `;
            } else if (usesDeviceRegistration) {
                // Device registration
                formContent = `
                <div class="no-credentials-required">
                    <i class="fas fa-mobile-alt"></i>
                    <strong>Device Registration</strong>
                    <p>This provider requires device registration. Follow provider-specific setup instructions.</p>
                </div>
                `;
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
                            <small><i class="fas fa-fingerprint"></i> ${getAuthTypeDescription(status)}</small>
                        </div>
                        <div id="status-${provider.name}" class="status-indicator">
                            ${getStatusIcon(status)}
                            ${getStatusText(status)}
                        </div>
                        ${formatTokenExpiration(status)}
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
        case 'authenticated':
        case 'AUTHENTICATED':
        case 'user_authenticated':
        case 'client_authenticated':
            return '<i class="fas fa-check-circle"></i>';
        case 'expired':
        case 'EXPIRED':
        case 'credentials_only':
            return '<i class="fas fa-exclamation-triangle"></i>';
        case 'not_authenticated':
        case 'NOT_AUTHENTICATED':
            return '<i class="fas fa-times-circle"></i>';
        case 'not_applicable':
        case 'NOT_APPLICABLE':
            return '<i class="fas fa-info-circle"></i>';
        default:
            return '<i class="fas fa-question-circle"></i>';
    }
}

function getStatusText(status) {
    if (!status) return 'Unknown';

    // Normalize auth_state to lowercase for comparison
    const authState = (status.auth_state || '').toLowerCase();

    switch (authState) {
        case 'authenticated':
            return 'Authenticated';
        case 'expired':
            return 'Token Expired (can refresh)';
        case 'not_authenticated':
            return 'Not Authenticated';
        case 'not_applicable':
            return 'No Auth Required';
        case 'user_authenticated':
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

                usernameInput.parentNode.insertBefore(infoText, passwordInput.parentNode);
            }

            // Reload auth status
            await loadAuthStatus();

            // Re-render to show updated status and expiration
            await renderCredentialsForms();

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
            // Update auth status in memory
            authStatus[providerName] = result;

            // Re-render to show updated status and expiration
            await renderCredentialsForms();

            if (result.is_ready) {
                showAlert('success', `${providerName} is ready to use`);
            } else {
                showAlert('warning', `${providerName} status: ${result.auth_state}`);
            }
        } else {
            statusEl.className = 'status-indicator status-error';
            statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Test failed';
            showAlert('error', `Test failed for ${providerName}`);
        }
    } catch (error) {
        statusEl.className = 'status-indicator status