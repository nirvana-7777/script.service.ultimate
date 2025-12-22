// Proxy Management Module

class ProxyManager {
    constructor(API_BASE) {
        this.API_BASE = API_BASE;
        this.providers = [];
    }

    // Initialize proxy manager
    init(providers) {
        this.providers = providers;
    }

    // Load proxy forms
    async loadProxyForms() {
        const proxyContainer = document.getElementById('proxy-container');

        if (!this.providers || this.providers.length === 0) {
            proxyContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-network-wired"></i>
                    <p>No providers available</p>
                    <p>Load providers from credentials tab first</p>
                </div>
            `;
            return;
        }

        const htmls = await Promise.all(this.providers.map(async (provider) => {
            return await this.createProxyCard(provider);
        }));

        proxyContainer.innerHTML = htmls.join('');
    }

    // Create proxy card HTML for a provider
    async createProxyCard(provider) {
        try {
            // Try to load existing proxy config
            const existingProxy = await this.getProxyConfig(provider.name);

            return `
            <div class="proxy-card" data-provider="${provider.name}">
                <div class="proxy-header">
                    ${provider.logo ? `<img src="${provider.logo}" alt="${provider.label}" class="proxy-logo">` : ''}
                    <div class="proxy-info">
                        <h3>${provider.label}</h3>
                        <div class="proxy-id">Proxy Configuration • ${provider.country}</div>
                        ${existingProxy ? `
                        <div class="proxy-status proxy-status-active">
                            <i class="fas fa-check-circle"></i> Proxy Configured
                            <span class="proxy-type-indicator proxy-type-${existingProxy.proxy_type || 'http'}">
                                ${(existingProxy.proxy_type || 'http').toUpperCase()}
                            </span>
                        </div>
                        ` : `
                        <div class="proxy-status proxy-status-inactive">
                            <i class="fas fa-times-circle"></i> No Proxy
                        </div>
                        `}
                    </div>
                </div>

                <div class="proxy-form-group">
                    <label for="proxy-host-${provider.name}">
                        <i class="fas fa-server"></i> Proxy Host
                    </label>
                    <input type="text"
                           id="proxy-host-${provider.name}"
                           class="proxy-form-control"
                           placeholder="proxy.example.com"
                           value="${existingProxy?.host || ''}">
                </div>

                <div class="proxy-form-group">
                    <label for="proxy-port-${provider.name}">
                        <i class="fas fa-plug"></i> Proxy Port
                    </label>
                    <input type="number"
                           id="proxy-port-${provider.name}"
                           class="proxy-form-control"
                           placeholder="8080"
                           min="1"
                           max="65535"
                           value="${existingProxy?.port || ''}">
                </div>

                <div class="proxy-form-group">
                    <label for="proxy-type-${provider.name}">
                        <i class="fas fa-network-wired"></i> Proxy Type
                    </label>
                    <select id="proxy-type-${provider.name}" class="proxy-select">
                        <option value="http" ${(!existingProxy || existingProxy.proxy_type === 'http') ? 'selected' : ''}>HTTP</option>
                        <option value="https" ${(existingProxy?.proxy_type === 'https') ? 'selected' : ''}>HTTPS</option>
                        <option value="socks4" ${(existingProxy?.proxy_type === 'socks4') ? 'selected' : ''}>SOCKS4</option>
                        <option value="socks5" ${(existingProxy?.proxy_type === 'socks5') ? 'selected' : ''}>SOCKS5</option>
                    </select>
                </div>

                <div class="proxy-form-group">
                    <label for="proxy-user-${provider.name}">
                        <i class="fas fa-user"></i> Username (Optional)
                    </label>
                    <input type="text"
                           id="proxy-user-${provider.name}"
                           class="proxy-form-control"
                           placeholder="proxyuser"
                           value="${existingProxy?.auth?.username || ''}">
                </div>

                <div class="proxy-form-group">
                    <label for="proxy-pass-${provider.name}">
                        <i class="fas fa-lock"></i> Password (Optional)
                    </label>
                    <input type="password"
                           id="proxy-pass-${provider.name}"
                           class="proxy-form-control"
                           placeholder="••••••••"
                           value="${existingProxy?.auth?.password || ''}">
                </div>

                ${this.createAdvancedProxySection(provider.name, existingProxy)}

                <div class="proxy-btn-group">
                    <button onclick="window.proxyManager.saveProxy('${provider.name}')" class="btn btn-primary">
                        <i class="fas fa-save"></i> ${existingProxy ? 'Update' : 'Save'} Proxy
                    </button>
                    ${existingProxy ? `
                    <button onclick="window.proxyManager.deleteProxy('${provider.name}')" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Delete Proxy
                    </button>
                    ` : ''}
                    <button onclick="window.proxyManager.testProxy('${provider.name}')" class="btn btn-success">
                        <i class="fas fa-vial"></i> Test Proxy
                    </button>
                </div>

                <div id="proxy-test-result-${provider.name}" class="proxy-test-result"></div>
            </div>
            `;
        } catch (error) {
            console.error(`Error creating proxy card for ${provider.name}:`, error);
            return ''; // Return empty string on error
        }
    }

    // Create advanced proxy section
    createAdvancedProxySection(providerName, existingProxy) {
        const scope = existingProxy?.scope || {
            api_calls: true,
            authentication: true,
            manifests: true,
            license: true,
            all: true
        };

        return `
        <div class="proxy-advanced-toggle" onclick="window.proxyManager.toggleAdvanced('${providerName}')">
            <i class="fas fa-chevron-down" id="proxy-advanced-icon-${providerName}"></i>
            <span>Advanced Options</span>
        </div>
        
        <div class="proxy-advanced-content" id="proxy-advanced-content-${providerName}">
            <div class="proxy-scope-settings">
                <h4><i class="fas fa-filter"></i> Proxy Scope</h4>
                <p>Select which operations should use this proxy:</p>
                <div class="scope-checkboxes">
                    <div class="scope-checkbox">
                        <input type="checkbox" 
                               id="proxy-scope-api-${providerName}" 
                               ${scope.all || scope.api_calls ? 'checked' : ''}>
                        <label for="proxy-scope-api-${providerName}">API Calls</label>
                    </div>
                    <div class="scope-checkbox">
                        <input type="checkbox" 
                               id="proxy-scope-auth-${providerName}" 
                               ${scope.all || scope.authentication ? 'checked' : ''}>
                        <label for="proxy-scope-auth-${providerName}">Authentication</label>
                    </div>
                    <div class="scope-checkbox">
                        <input type="checkbox" 
                               id="proxy-scope-manifests-${providerName}" 
                               ${scope.all || scope.manifests ? 'checked' : ''}>
                        <label for="proxy-scope-manifests-${providerName}">Manifests</label>
                    </div>
                    <div class="scope-checkbox">
                        <input type="checkbox" 
                               id="proxy-scope-license-${providerName}" 
                               ${scope.all || scope.license ? 'checked' : ''}>
                        <label for="proxy-scope-license-${providerName}">License Requests</label>
                    </div>
                    <div class="scope-checkbox">
                        <input type="checkbox" 
                               id="proxy-scope-all-${providerName}" 
                               ${scope.all ? 'checked' : ''}>
                        <label for="proxy-scope-all-${providerName}">All Operations</label>
                    </div>
                </div>
            </div>

            <div class="proxy-form-group">
                <label for="proxy-timeout-${providerName}">
                    <i class="fas fa-clock"></i> Timeout (seconds)
                </label>
                <input type="number"
                       id="proxy-timeout-${providerName}"
                       class="proxy-form-control"
                       placeholder="30"
                       min="1"
                       max="300"
                       value="${existingProxy?.timeout || 30}">
            </div>

            <div class="proxy-form-group">
                <label for="proxy-verify-ssl-${providerName}" style="display: flex; align-items: center;">
                    <input type="checkbox" 
                           id="proxy-verify-ssl-${providerName}" 
                           ${existingProxy?.verify_ssl !== false ? 'checked' : ''}
                           style="margin-right: 8px;">
                    Verify SSL Certificate
                </label>
            </div>
        </div>
        `;
    }

    // Get proxy configuration from API
    async getProxyConfig(providerName) {
        try {
            const response = await fetch(`${this.API_BASE}/api/providers/${providerName}/proxy`);
            if (response.ok) {
                const data = await response.json();
                return data.proxy_config || null;
            }
            return null;
        } catch (error) {
            console.error(`Error getting proxy config for ${providerName}:`, error);
            return null;
        }
    }

    // Save proxy configuration
    async saveProxy(providerName) {
        const host = document.getElementById(`proxy-host-${providerName}`).value.trim();
        const port = document.getElementById(`proxy-port-${providerName}`).value.trim();
        const type = document.getElementById(`proxy-type-${providerName}`).value;
        const user = document.getElementById(`proxy-user-${providerName}`).value.trim();
        const pass = document.getElementById(`proxy-pass-${providerName}`).value;

        // Advanced options
        const timeout = document.getElementById(`proxy-timeout-${providerName}`)?.value || 30;
        const verifySsl = document.getElementById(`proxy-verify-ssl-${providerName}`)?.checked !== false;

        // Scope settings
        const scope = {
            api_calls: document.getElementById(`proxy-scope-api-${providerName}`)?.checked || false,
            authentication: document.getElementById(`proxy-scope-auth-${providerName}`)?.checked || false,
            manifests: document.getElementById(`proxy-scope-manifests-${providerName}`)?.checked || false,
            license: document.getElementById(`proxy-scope-license-${providerName}`)?.checked || false,
            all: document.getElementById(`proxy-scope-all-${providerName}`)?.checked || false
        };

        if (!host || !port) {
            this.showProxyAlert('error', 'Please fill in at least Host and Port fields', providerName);
            return;
        }

        const proxyConfig = {
            host,
            port: parseInt(port),
            proxy_type: type,
            timeout: parseInt(timeout),
            verify_ssl: verifySsl,
            scope: scope
        };

        if (user) {
            proxyConfig.auth = { username: user };
            if (pass) {
                proxyConfig.auth.password = pass;
            }
        }

        try {
            const response = await fetch(`${this.API_BASE}/api/providers/${providerName}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(proxyConfig)
            });

            if (response.ok) {
                this.showProxyAlert('success', `Proxy configuration saved for ${providerName}`, providerName);
                // Clear password field
                if (document.getElementById(`proxy-pass-${providerName}`)) {
                    document.getElementById(`proxy-pass-${providerName}`).value = '';
                }
                // Reload proxy form to show updated status
                await this.loadProxyForms();
            } else {
                const result = await response.json();
                this.showProxyAlert('error', result.error || `Failed to save proxy for ${providerName}`, providerName);
            }
        } catch (error) {
            this.showProxyAlert('error', `Network error: ${error.message}`, providerName);
            console.error('Proxy save error:', error);
        }
    }

    // Delete proxy configuration
    async deleteProxy(providerName) {
        if (!confirm(`Delete proxy configuration for ${providerName}?`)) return;

        try {
            const response = await fetch(`${this.API_BASE}/api/providers/${providerName}/proxy`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showProxyAlert('success', `Proxy configuration deleted for ${providerName}`, providerName);
                // Reload proxy form
                await this.loadProxyForms();
            } else {
                const result = await response.json();
                this.showProxyAlert('error', result.error || `Failed to delete proxy for ${providerName}`, providerName);
            }
        } catch (error) {
            this.showProxyAlert('error', `Network error: ${error.message}`, providerName);
            console.error('Proxy delete error:', error);
        }
    }

    // Test proxy connection
    async testProxy(providerName) {
        const testResultEl = document.getElementById(`proxy-test-result-${providerName}`);
        if (testResultEl) {
            testResultEl.innerHTML = '<span class="loader"></span> Testing proxy connection...';
            testResultEl.className = 'proxy-test-result';
        }

        try {
            // Try to fetch a test endpoint through the provider
            const response = await fetch(`${this.API_BASE}/api/providers/${providerName}/channels?limit=1`);

            if (response.ok) {
                if (testResultEl) {
                    testResultEl.innerHTML = '<i class="fas fa-check-circle"></i> Proxy connection successful!';
                    testResultEl.className = 'proxy-test-result success';
                }
                this.showProxyAlert('success', `Proxy test passed for ${providerName}`, providerName);
            } else {
                if (testResultEl) {
                    testResultEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> Proxy test failed (HTTP ${response.status})`;
                    testResultEl.className = 'proxy-test-result error';
                }
                this.showProxyAlert('error', `Proxy test failed for ${providerName} (HTTP ${response.status})`, providerName);
            }
        } catch (error) {
            if (testResultEl) {
                testResultEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> Network error: ${error.message}`;
                testResultEl.className = 'proxy-test-result error';
            }
            this.showProxyAlert('error', `Proxy test failed: ${error.message}`, providerName);
            console.error('Proxy test error:', error);
        }
    }

    // Toggle advanced options
    toggleAdvanced(providerName) {
        const contentEl = document.getElementById(`proxy-advanced-content-${providerName}`);
        const iconEl = document.getElementById(`proxy-advanced-icon-${providerName}`);

        if (contentEl && iconEl) {
            const isExpanded = contentEl.classList.contains('expanded');
            if (isExpanded) {
                contentEl.classList.remove('expanded');
                iconEl.classList.remove('fa-chevron-up');
                iconEl.classList.add('fa-chevron-down');
            } else {
                contentEl.classList.add('expanded');
                iconEl.classList.remove('fa-chevron-down');
                iconEl.classList.add('fa-chevron-up');
            }
        }
    }

    // Show alert for proxy operations
    showProxyAlert(type, message, providerName = null) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <div>${providerName ? `<strong>${providerName}:</strong> ` : ''}${message}</div>
        `;

        // Insert at beginning of proxy container
        const proxyContainer = document.getElementById('proxy-container');
        if (proxyContainer) {
            proxyContainer.insertBefore(alert, proxyContainer.firstChild);
        } else {
            // Fallback to card body
            const cardBody = document.querySelector('.card-body');
            if (cardBody) {
                cardBody.insertBefore(alert, cardBody.firstChild);
            }
        }

        // Remove after 5 seconds
        setTimeout(() => alert.remove(), 5000);
    }
}

// Make ProxyManager globally available
window.ProxyManager = ProxyManager;

// Initialize proxy manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.proxyManager = new ProxyManager(window.location.origin);
});