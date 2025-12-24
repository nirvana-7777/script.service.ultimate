// Provider Enable/Disable Manager
class ProviderEnableManager {
    constructor() {
        this.enabledStatus = {};
        this.currentFilter = 'all'; // 'all', 'enabled', 'disabled'
        this.allProviders = [];
        this.providers = [];
    }

    async init(allProvidersMetadata) {
        // allProvidersMetadata now comes from /api/providers response's "all_providers" field
        // It contains ALL providers (enabled and disabled) with metadata
        this.allProviders = allProvidersMetadata || [];

        // Extract just the enabled providers for backward compatibility
        this.providers = this.allProviders.filter(p => p.enabled && p.instance_ready);

        // Build enabledStatus from metadata (no separate API call needed)
        this.enabledStatus = {};
        this.allProviders.forEach(provider => {
            this.enabledStatus[provider.name] = {
                enabled: provider.enabled,
                source: 'config', // Could be enhanced to detect source from metadata
                can_modify: true  // All providers can be toggled via POST
            };
        });

        console.log('Loaded enabled status from metadata:', this.enabledStatus);
    }

    isEnabled(providerName) {
        return this.enabledStatus[providerName]?.enabled !== false;
    }

    canModify(providerName) {
        return this.enabledStatus[providerName]?.can_modify !== false;
    }

    getSource(providerName) {
        return this.enabledStatus[providerName]?.source || 'default';
    }

    async toggleProvider(providerName, newState) {
        const statusInfo = this.enabledStatus[providerName];

        if (!statusInfo?.can_modify) {
            showAlert('error', `Cannot modify ${providerName} - controlled by ${statusInfo?.source || 'external source'}`);
            return false;
        }

        try {
            const response = await fetch(`${API_BASE}/api/providers/${providerName}/enabled`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: newState })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to update status');
            }

            const result = await response.json();

            // Update local status
            this.enabledStatus[providerName] = {
                enabled: newState,
                source: result.source || 'file',
                can_modify: true
            };

            // Also update in allProviders array
            const providerIndex = this.allProviders.findIndex(p => p.name === providerName);
            if (providerIndex !== -1) {
                this.allProviders[providerIndex].enabled = newState;
            }

            // Rebuild enabled providers list
            this.providers = this.allProviders.filter(p => p.enabled && p.instance_ready);

            return true;
        } catch (error) {
            console.error('Error toggling provider:', error);
            showAlert('error', `Failed to ${newState ? 'enable' : 'disable'} ${providerName}: ${error.message}`);
            return false;
        }
    }

    setFilter(filter) {
        this.currentFilter = filter;
        this.applyFilter();
    }

    applyFilter() {
        const cards = document.querySelectorAll('.provider-card');
        let visibleCount = 0;

        cards.forEach(card => {
            const providerName = card.dataset.provider;
            const isEnabled = this.isEnabled(providerName);

            let shouldShow = false;
            switch (this.currentFilter) {
                case 'all':
                    shouldShow = true;
                    break;
                case 'enabled':
                    shouldShow = isEnabled;
                    break;
                case 'disabled':
                    shouldShow = !isEnabled;
                    break;
            }

            if (shouldShow) {
                card.style.display = '';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        // Update filter info
        this.updateFilterInfo(visibleCount);
    }

    updateFilterInfo(visibleCount) {
        const filterInfo = document.querySelector('.filter-info');
        if (filterInfo) {
            const totalEnabled = Object.values(this.enabledStatus).filter(s => s.enabled).length;
            const totalDisabled = Object.values(this.enabledStatus).filter(s => !s.enabled).length;

            let infoText = '';
            switch (this.currentFilter) {
                case 'all':
                    infoText = `Showing <strong>all ${visibleCount}</strong> providers (<strong>${totalEnabled}</strong> enabled, <strong>${totalDisabled}</strong> disabled)`;
                    break;
                case 'enabled':
                    infoText = `Showing <strong>${visibleCount}</strong> enabled providers`;
                    break;
                case 'disabled':
                    infoText = `Showing <strong>${visibleCount}</strong> disabled providers`;
                    break;
            }
            filterInfo.innerHTML = infoText;
        }
    }

    shouldShowInTab(providerName, tabId) {
        // In credentials tab, show all (enabled and disabled)
        if (tabId === 'credentials') {
            return true;
        }

        // In other tabs (proxy, epg-mapping), only show enabled
        return this.isEnabled(providerName);
    }

    getFilteredProviders(tabId) {
        if (!this.allProviders) return [];

        // In credentials tab, show all providers (enabled and disabled)
        if (tabId === 'credentials') {
            return this.allProviders;
        }

        // In other tabs (proxy, epg-mapping), only show enabled providers
        return this.allProviders.filter(provider =>
            provider.enabled && provider.instance_ready
        );
    }
}

// Create global instance
window.providerEnableManager = new ProviderEnableManager();

// Add filter UI to credentials tab
function addFilterUI() {
    const credentialsTab = document.getElementById('tab-credentials');
    const cardBody = credentialsTab.querySelector('.card-body');

    // Check if filter already exists
    if (document.querySelector('.filter-section')) {
        return;
    }

    const filterHTML = `
        <div class="filter-section">
            <div>
                <label for="provider-filter">
                    <i class="fas fa-filter"></i> Show:
                </label>
                <select id="provider-filter" class="filter-select">
                    <option value="all">All Providers</option>
                    <option value="enabled">Enabled Only</option>
                    <option value="disabled">Disabled Only</option>
                </select>
            </div>
            <div class="filter-info">
                Loading...
            </div>
        </div>
    `;

    // Insert after the alert
    const alert = cardBody.querySelector('.alert');
    if (alert) {
        alert.insertAdjacentHTML('afterend', filterHTML);
    } else {
        cardBody.insertAdjacentHTML('afterbegin', filterHTML);
    }

    // Add event listener
    const filterSelect = document.getElementById('provider-filter');
    filterSelect.addEventListener('change', (e) => {
        window.providerEnableManager.setFilter(e.target.value);
    });
}

// Create toggle switch HTML
function createToggleSwitch(providerName, isEnabled, canModify) {
    const toggleId = `toggle-${providerName}`;
    return `
        <label class="provider-toggle" title="${canModify ? 'Click to toggle' : 'Cannot modify - controlled externally'}">
            <input type="checkbox" 
                   id="${toggleId}"
                   ${isEnabled ? 'checked' : ''}
                   ${!canModify ? 'disabled' : ''}
                   onchange="handleProviderToggle('${providerName}', this)">
            <span class="toggle-slider"></span>
        </label>
    `;
}

// Handle toggle change
async function handleProviderToggle(providerName, checkbox) {
    const slider = checkbox.nextElementSibling;
    const card = checkbox.closest('.provider-card');

    // Add loading state
    slider.classList.add('loading');
    checkbox.disabled = true;

    const newState = checkbox.checked;
    const success = await window.providerEnableManager.toggleProvider(providerName, newState);

    if (success) {
        // Update card appearance
        if (newState) {
            card.classList.remove('disabled');
            showAlert('success', `${providerName} enabled`);
        } else {
            card.classList.add('disabled');
            showAlert('success', `${providerName} disabled`);
        }

        // Update filter info
        window.providerEnableManager.applyFilter();
    } else {
        // Revert checkbox on failure
        checkbox.checked = !newState;
    }

    // Remove loading state
    slider.classList.remove('loading');
    checkbox.disabled = !window.providerEnableManager.canModify(providerName);
}

// Export for global use
window.handleProviderToggle = handleProviderToggle;
window.addFilterUI = addFilterUI;
window.createToggleSwitch = createToggleSwitch;