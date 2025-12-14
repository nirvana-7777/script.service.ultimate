// EPG Mapping Manager
class EPGMappingManager {
    constructor() {
        this.providers = [];
        this.currentProvider = null;
        this.epgChannels = [];
        this.channelData = [];
        this.fuzzySet = null;
        this.unsavedChanges = false;
        this.autoSaveTimeout = null;

        // Get API base from current location
        this.apiBase = window.location.origin;

        this.init();
    }

    init() {
        // Don't load providers on init - wait for tab activation
        this.setupEventListeners();
        this.createSaveIndicator();
        this.initialized = false;
    }

    async loadProviders() {
        // Only load once
        if (this.initialized) return;

        try {
            const response = await fetch(`${this.apiBase}/api/providers`);
            if (!response.ok) throw new Error('Failed to load providers');

            const data = await response.json();
            this.providers = data.providers;
            this.renderProviderSelector();
            this.initialized = true;
        } catch (error) {
            this.showError('Failed to load providers', error);
        }
    }

    renderProviderSelector() {
        const container = document.getElementById('epg-mapping-container');
        if (!container) return;

        container.innerHTML = `
            <div class="epg-mapping-container">
                <div class="mapping-header">
                    <div class="provider-selector">
                        <select id="epg-provider-select">
                            <option value="">Select a provider...</option>
                            ${this.providers.map(p =>
                                `<option value="${p.name}">${p.label} (${p.name})</option>`
                            ).join('')}
                        </select>
                        <button id="epg-load-provider" class="btn btn-primary">
                            <i class="fas fa-sync"></i> Load Channels
                        </button>
                    </div>
                    <div class="header-stats">
                        <span class="stat mapped"><i class="fas fa-check-circle"></i> Mapped: <span id="stat-mapped">0</span></span>
                        <span class="stat recommended"><i class="fas fa-star"></i> Recommended: <span id="stat-recommended">0</span></span>
                        <span class="stat unmapped"><i class="fas fa-question-circle"></i> Unmapped: <span id="stat-unmapped">0</span></span>
                    </div>
                </div>

                <div class="mapping-controls" style="display: none;" id="epg-controls">
                    <div class="search-box">
                        <i class="fas fa-search"></i>
                        <input type="text" id="epg-search" placeholder="Search channels or EPG IDs...">
                    </div>
                    <div class="filters">
                        <label class="filter-checkbox">
                            <input type="checkbox" id="filter-mapped" checked>
                            <span>Mapped</span>
                        </label>
                        <label class="filter-checkbox">
                            <input type="checkbox" id="filter-recommended" checked>
                            <span>Recommended</span>
                        </label>
                        <label class="filter-checkbox">
                            <input type="checkbox" id="filter-unmapped" checked>
                            <span>Unmapped</span>
                        </label>
                    </div>
                </div>

                <div class="channel-mapping-list" id="channel-list" style="display: none;"></div>

                <div class="bulk-actions" id="bulk-actions" style="display: none;">
                    <button id="btn-bulk-confirm" class="btn btn-success">
                        <i class="fas fa-check-double"></i> Confirm All Recommended
                    </button>
                    <button id="btn-save-changes" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Changes
                    </button>
                    <button id="btn-export-mappings" class="btn btn-secondary">
                        <i class="fas fa-download"></i> Export Mappings
                    </button>
                    <button id="btn-import-mappings" class="btn btn-secondary">
                        <i class="fas fa-upload"></i> Import Mappings
                    </button>
                </div>
            </div>

            <!-- EPG Preview Modal -->
            <div class="epg-preview-modal" id="epg-preview-modal">
                <div class="epg-preview-content">
                    <div class="epg-preview-header">
                        <h3><i class="fas fa-tv"></i> EPG Preview</h3>
                        <button class="btn btn-sm btn-danger" id="close-preview">
                            <i class="fas fa-times"></i> Close
                        </button>
                    </div>
                    <div class="epg-preview-body" id="epg-preview-body"></div>
                </div>
            </div>
        `;

        this.setupDynamicEventListeners();
    }

    setupEventListeners() {
        // Listen for tab switches - this is the key change
        const checkTabSwitch = () => {
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    if (tab.dataset.tab === 'epg-mapping') {
                        // Only load providers when EPG tab is first activated
                        if (!this.initialized) {
                            this.loadProviders();
                        }
                    }
                });
            });
        };

        // Check if DOM is already loaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', checkTabSwitch);
        } else {
            checkTabSwitch();
        }
    }

    setupDynamicEventListeners() {
        const loadBtn = document.getElementById('epg-load-provider');
        if (loadBtn) {
            loadBtn.addEventListener('click', () => {
                const select = document.getElementById('epg-provider-select');
                this.currentProvider = select.value;
                if (this.currentProvider) {
                    this.loadProviderData(this.currentProvider);
                }
            });
        }

        const searchInput = document.getElementById('epg-search');
        if (searchInput) {
            searchInput.addEventListener('input', debounce(() => {
                this.filterChannels();
            }, 300));
        }

        ['mapped', 'recommended', 'unmapped'].forEach(filter => {
            const checkbox = document.getElementById(`filter-${filter}`);
            if (checkbox) {
                checkbox.addEventListener('change', () => {
                    this.filterChannels();
                });
            }
        });

        const bulkConfirm = document.getElementById('btn-bulk-confirm');
        if (bulkConfirm) {
            bulkConfirm.addEventListener('click', () => {
                this.bulkConfirmRecommended();
            });
        }

        const saveBtn = document.getElementById('btn-save-changes');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                this.saveMappings();
            });
        }

        const exportBtn = document.getElementById('btn-export-mappings');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportMappings();
            });
        }

        const importBtn = document.getElementById('btn-import-mappings');
        if (importBtn) {
            importBtn.addEventListener('click', () => {
                this.importMappings();
            });
        }

        const closePreview = document.getElementById('close-preview');
        if (closePreview) {
            closePreview.addEventListener('click', () => {
                document.getElementById('epg-preview-modal').style.display = 'none';
            });
        }

        const modal = document.getElementById('epg-preview-modal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target.id === 'epg-preview-modal') {
                    e.target.style.display = 'none';
                }
            });
        }
    }

    async loadProviderData(providerName) {
        try {
            // Show loading in the channel list area only
            const controlsContainer = document.getElementById('epg-controls');
            const channelList = document.getElementById('channel-list');
            const bulkActions = document.getElementById('bulk-actions');

            if (controlsContainer) controlsContainer.style.display = 'none';
            if (channelList) {
                channelList.style.display = 'block';
                channelList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-spinner fa-spin loader"></i>
                        <p>Loading EPG data...</p>
                    </div>
                `;
            }
            if (bulkActions) bulkActions.style.display = 'none';

            // First check EPG status
            let epgStatusResponse;
             try {
                epgStatusResponse = await fetch(`${this.apiBase}/api/epg/status`);
                if (epgStatusResponse.ok) {
                    const epgStatus = await epgStatusResponse.json();
                    if (!epgStatus.configured || epgStatus.epg_url === "https://example.com/epg.xml.gz") {
                        throw new Error('EPG URL not configured. Please configure a valid EPG URL in the Advanced tab first.');
                    }
                    if (!epgStatus.cache_valid) {
                        console.log('EPG cache not valid, will attempt to download...');
                    }
                }
            } catch (statusError) {
                console.warn('Could not check EPG status:', statusError);
            }

            // Load all data in parallel
            const [channelsResponse, mappingsResponse, epgResponse] = await Promise.all([
                fetch(`${this.apiBase}/api/providers/${providerName}/channels`),
                fetch(`${this.apiBase}/api/providers/${providerName}/epg-mapping`),
                fetch(`${this.apiBase}/api/epg/xmltv-channels`)
            ]);

            if (!channelsResponse.ok) throw new Error('Failed to load provider channels');

            if (!epgResponse.ok) {
                const epgError = await epgResponse.json();
                throw new Error(epgError.error || 'Failed to load EPG channels. Please check EPG configuration in Advanced tab.');
            }

            const providerChannels = await channelsResponse.json();
            const currentMappings = mappingsResponse.ok ? await mappingsResponse.json() : { mapping: {} };
            const epgData = await epgResponse.json();

            this.epgChannels = epgData.channels || [];
            this.fuzzySet = new FuzzySet(this.epgChannels);

            this.channelData = providerChannels.channels.map(channel => {
                let currentEpgId = null;
                const mappingValue = currentMappings.mapping?.[channel.id];
                if (typeof mappingValue === 'string') {
                    currentEpgId = mappingValue;
                } else if (mappingValue && mappingValue.epg_id) {
                    currentEpgId = mappingValue.epg_id;
                }

                const suggestions = this.getSuggestions(channel.name);

                return {
                    ...channel,
                    currentEpgId,
                    suggestions: suggestions.slice(0, 3),
                    status: this.calculateStatus(channel, currentEpgId, suggestions)
                };
            });

            if (controlsContainer) controlsContainer.style.display = 'flex';
            if (channelList) channelList.style.display = 'block';
            if (bulkActions) bulkActions.style.display = 'flex';

            this.updateStats();
            this.renderChannelList();

        } catch (error) {
            this.showError('Failed to load provider data', error);
        }
    }

    getSuggestions(channelName) {
        if (!this.fuzzySet || !channelName) return [];

        const results = this.fuzzySet.get(channelName);
        if (!results) return [];

        return results.map(([score, epgId]) => ({
            epgId,
            score: Math.round(score * 100),
            name: epgId
        }));
    }

    calculateStatus(channel, currentEpgId, suggestions) {
        if (currentEpgId) return 'mapped';
        const hasGoodSuggestion = suggestions.some(s => s.score > 80);
        return hasGoodSuggestion ? 'recommended' : 'unmapped';
    }

    renderChannelList() {
        const container = document.getElementById('channel-list');
        if (!container || this.channelData.length === 0) {
            if (container) {
                container.innerHTML = `
                    <div class="no-channels-message">
                        <i class="fas fa-tv"></i>
                        <p>No channels found for this provider.</p>
                    </div>
                `;
            }
            return;
        }

        const filteredChannels = this.getFilteredChannels();

        container.innerHTML = filteredChannels.map(channel => `
            <div class="channel-card status-${channel.status}" data-channel-id="${channel.id}">
                <div class="channel-info">
                    ${channel.logo ? `<img src="${channel.logo}" alt="${this.escapeHtml(channel.name)}" class="channel-logo" onerror="this.style.display='none'">` : ''}
                    <div class="channel-details">
                        <h4>${this.escapeHtml(channel.name)}</h4>
                        <div class="channel-id">ID: ${this.escapeHtml(channel.id)}</div>
                        <div class="channel-source">${this.escapeHtml(this.currentProvider)}</div>
                    </div>
                </div>

                <div class="mapping-control">
                    <select class="epg-selector" data-channel="${this.escapeHtml(channel.id)}">
                        <option value="">-- Select EPG ID --</option>
                        <option value="${this.escapeHtml(channel.id)}" ${channel.currentEpgId === channel.id ? 'selected' : ''}>
                            ${this.escapeHtml(channel.id)} (Use channel ID)
                        </option>
                        ${this.epgChannels.map(epgId => `
                            <option value="${this.escapeHtml(epgId)}" ${channel.currentEpgId === epgId ? 'selected' : ''}>
                                ${this.escapeHtml(epgId)}
                            </option>
                        `).join('')}
                    </select>

                    <div class="mapping-status">
                        <span class="status-badge ${channel.status}">
                            ${this.getStatusIcon(channel.status)} ${channel.status.charAt(0).toUpperCase() + channel.status.slice(1)}
                        </span>

                        ${channel.status === 'recommended' && channel.suggestions.length > 0 ? `
                            <div class="epg-suggestions">
                                <small>Suggestions:</small>
                                ${channel.suggestions.map(s => `
                                    <span class="suggestion-tag"
                                          data-epg-id="${this.escapeHtml(s.epgId)}"
                                          data-channel="${this.escapeHtml(channel.id)}"
                                          title="Match: ${s.score}%">
                                        ${this.escapeHtml(s.epgId)}
                                    </span>
                                `).join('')}
                            </div>
                        ` : ''}

                        ${channel.status === 'unmapped' && channel.suggestions.length > 0 ? `
                            <div class="epg-suggestions">
                                <small>Low confidence matches:</small>
                                ${channel.suggestions.slice(0, 2).map(s => `
                                    <span class="suggestion-tag"
                                          data-epg-id="${this.escapeHtml(s.epgId)}"
                                          data-channel="${this.escapeHtml(channel.id)}"
                                          title="Match: ${s.score}%">
                                        ${this.escapeHtml(s.epgId)} (${s.score}%)
                                    </span>
                                `).join('')}
                            </div>
                        ` : ''}

                        ${channel.currentEpgId ? `
                            <div class="epg-preview">
                                <a href="#" class="preview-link" data-epg-id="${this.escapeHtml(channel.currentEpgId)}">
                                    <i class="fas fa-eye"></i> Preview EPG
                                </a>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `).join('');

        this.setupChannelEventListeners();
    }

    setupChannelEventListeners() {
        document.querySelectorAll('.epg-selector').forEach(select => {
            select.addEventListener('change', (e) => {
                const channelId = e.target.dataset.channel;
                const epgId = e.target.value;
                this.updateChannelMapping(channelId, epgId);
            });
        });

        document.querySelectorAll('.suggestion-tag').forEach(tag => {
            tag.addEventListener('click', (e) => {
                e.preventDefault();
                const channelId = e.target.dataset.channel;
                const epgId = e.target.dataset.epgId;

                const selector = document.querySelector(`.epg-selector[data-channel="${channelId}"]`);
                if (selector) {
                    selector.value = epgId;
                    this.updateChannelMapping(channelId, epgId);
                }
            });
        });

        document.querySelectorAll('.preview-link').forEach(link => {
            link.addEventListener('click', async (e) => {
                e.preventDefault();
                const epgId = e.target.closest('.preview-link').dataset.epgId;
                await this.showEPGPreview(epgId);
            });
        });
    }

    updateChannelMapping(channelId, epgId) {
        const channel = this.channelData.find(c => c.id === channelId);
        if (!channel) return;

        channel.currentEpgId = epgId;
        channel.status = epgId ? 'mapped' : 'unmapped';

        const card = document.querySelector(`.channel-card[data-channel-id="${channelId}"]`);
        if (card) {
            card.className = `channel-card status-${channel.status}`;

            const badge = card.querySelector('.status-badge');
            if (badge) {
                badge.className = `status-badge ${channel.status}`;
                badge.innerHTML = `${this.getStatusIcon(channel.status)} ${channel.status.charAt(0).toUpperCase() + channel.status.slice(1)}`;
            }

            const previewContainer = card.querySelector('.epg-preview');
            if (previewContainer) {
                if (epgId) {
                    previewContainer.innerHTML = `
                        <a href="#" class="preview-link" data-epg-id="${this.escapeHtml(epgId)}">
                            <i class="fas fa-eye"></i> Preview EPG
                        </a>
                    `;
                    const newLink = previewContainer.querySelector('.preview-link');
                    if (newLink) {
                        newLink.addEventListener('click', async (e) => {
                            e.preventDefault();
                            await this.showEPGPreview(epgId);
                        });
                    }
                } else {
                    previewContainer.innerHTML = '';
                }
            }
        }

        this.updateStats();
        this.scheduleAutoSave();
    }

    getFilteredChannels() {
        const showMapped = document.getElementById('filter-mapped')?.checked ?? true;
        const showRecommended = document.getElementById('filter-recommended')?.checked ?? true;
        const showUnmapped = document.getElementById('filter-unmapped')?.checked ?? true;
        const searchTerm = document.getElementById('epg-search')?.value.toLowerCase() || '';

        return this.channelData.filter(channel => {
            if (channel.status === 'mapped' && !showMapped) return false;
            if (channel.status === 'recommended' && !showRecommended) return false;
            if (channel.status === 'unmapped' && !showUnmapped) return false;

            if (searchTerm) {
                return channel.name.toLowerCase().includes(searchTerm) ||
                       channel.id.toLowerCase().includes(searchTerm) ||
                       (channel.currentEpgId && channel.currentEpgId.toLowerCase().includes(searchTerm)) ||
                       channel.suggestions.some(s => s.epgId.toLowerCase().includes(searchTerm));
            }

            return true;
        });
    }

    filterChannels() {
        this.renderChannelList();
    }

    updateStats() {
        const mapped = this.channelData.filter(c => c.status === 'mapped').length;
        const recommended = this.channelData.filter(c => c.status === 'recommended').length;
        const unmapped = this.channelData.filter(c => c.status === 'unmapped').length;

        const mappedEl = document.getElementById('stat-mapped');
        const recommendedEl = document.getElementById('stat-recommended');
        const unmappedEl = document.getElementById('stat-unmapped');

        if (mappedEl) mappedEl.textContent = mapped;
        if (recommendedEl) recommendedEl.textContent = recommended;
        if (unmappedEl) unmappedEl.textContent = unmapped;
    }

    getStatusIcon(status) {
        switch(status) {
            case 'mapped': return '<i class="fas fa-check"></i>';
            case 'recommended': return '<i class="fas fa-star"></i>';
            case 'unmapped': return '<i class="fas fa-question"></i>';
            default: return '<i class="fas fa-circle"></i>';
        }
    }

    async showEPGPreview(epgId) {
        try {
            const response = await fetch(`${this.apiBase}/api/epg/preview/${encodeURIComponent(epgId)}`);
            if (!response.ok) throw new Error('No EPG data available');

            const epgData = await response.json();
            const modal = document.getElementById('epg-preview-modal');
            const body = document.getElementById('epg-preview-body');

            body.innerHTML = `
                <h4>EPG Data for: ${this.escapeHtml(epgId)}</h4>
                ${epgData.programs && epgData.programs.length > 0 ? `
                    <div class="epg-programs">
                        ${epgData.programs.slice(0, 5).map(program => `
                            <div class="epg-program">
                                <div class="epg-program-time">
                                    ${new Date(program.start * 1000).toLocaleString()} -
                                    ${new Date(program.end * 1000).toLocaleTimeString()}
                                </div>
                                <div class="epg-program-title">
                                    <strong>${this.escapeHtml(program.title || 'No title')}</strong>
                                    ${program.episode_name ? `<br><em>${this.escapeHtml(program.episode_name)}</em>` : ''}
                                </div>
                                <div class="epg-program-desc">
                                    ${this.escapeHtml(program.description || 'No description available.')}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                ` : '<p>No program data available for this channel.</p>'}
            `;

            modal.style.display = 'flex';
        } catch (error) {
            this.showError('Failed to load EPG preview', error);
        }
    }

    bulkConfirmRecommended() {
        const recommendedChannels = this.channelData.filter(c => c.status === 'recommended');

        if (recommendedChannels.length === 0) {
            alert('No recommended channels to confirm.');
            return;
        }

        if (!confirm(`Confirm ${recommendedChannels.length} recommended mappings?`)) {
            return;
        }

        recommendedChannels.forEach(channel => {
            if (channel.suggestions.length > 0) {
                const bestSuggestion = channel.suggestions[0];
                channel.currentEpgId = bestSuggestion.epgId;
                channel.status = 'mapped';
            }
        });

        this.updateStats();
        this.renderChannelList();
        this.scheduleAutoSave();

        alert(`Confirmed ${recommendedChannels.length} mappings. Don't forget to save!`);
    }

    scheduleAutoSave() {
        this.unsavedChanges = true;
        this.showSaveIndicator('Unsaved changes');

        if (this.autoSaveTimeout) {
            clearTimeout(this.autoSaveTimeout);
        }

        this.autoSaveTimeout = setTimeout(() => {
            this.saveMappings(true);
        }, 5000);
    }

    async saveMappings(isAutoSave = false) {
        if (!this.currentProvider) return;

        if (this.autoSaveTimeout) {
            clearTimeout(this.autoSaveTimeout);
            this.autoSaveTimeout = null;
        }

        const mappings = {};
        this.channelData.forEach(channel => {
            if (channel.currentEpgId) {
                mappings[channel.id] = channel.currentEpgId;
            }
        });

        try {
            this.showSaveIndicator('Saving...');

            const response = await fetch(`${this.apiBase}/api/providers/${this.currentProvider}/epg-mapping`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mapping: mappings })
            });

            if (response.ok) {
                this.unsavedChanges = false;
                this.showSaveIndicator('Saved successfully!', true);

                if (!isAutoSave) {
                    setTimeout(() => {
                        this.hideSaveIndicator();
                    }, 2000);
                }
            } else {
                throw new Error('Save failed');
            }
        } catch (error) {
            this.showSaveIndicator('Save failed!', false);
            console.error('Save error:', error);
        }
    }

    exportMappings() {
        if (!this.currentProvider) {
            alert('Please load a provider first.');
            return;
        }

        const mappings = {};
        this.channelData.forEach(channel => {
            if (channel.currentEpgId) {
                mappings[channel.id] = channel.currentEpgId;
            }
        });

        const data = {
            provider: this.currentProvider,
            mapping: mappings,
            exported_at: new Date().toISOString()
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${this.currentProvider}_epg_mapping_${new Date().toISOString().slice(0,10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        alert('Mappings exported successfully!');
    }

    importMappings() {
        if (!this.currentProvider) {
            alert('Please load a provider first.');
            return;
        }

        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';

        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                const text = await file.text();
                const data = JSON.parse(text);

                if (!data.mapping || typeof data.mapping !== 'object') {
                    throw new Error('Invalid mapping file format');
                }

                Object.entries(data.mapping).forEach(([channelId, mappingValue]) => {
                    const channel = this.channelData.find(c => c.id === channelId);
                    if (channel) {
                        if (typeof mappingValue === 'string') {
                            channel.currentEpgId = mappingValue;
                        } else if (mappingValue && mappingValue.epg_id) {
                            channel.currentEpgId = mappingValue.epg_id;
                        }
                        channel.status = 'mapped';
                    }
                });

                this.updateStats();
                this.renderChannelList();
                this.scheduleAutoSave();

                alert(`Imported ${Object.keys(data.mapping).length} mappings successfully!`);

            } catch (error) {
                alert(`Import failed: ${error.message}`);
            }
        };

        input.click();
    }

    createSaveIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'save-indicator';
        indicator.id = 'save-indicator';
        indicator.style.display = 'none';
        document.body.appendChild(indicator);
    }

    showSaveIndicator(message, isSuccess = null) {
        const indicator = document.getElementById('save-indicator');
        if (!indicator) return;

        indicator.innerHTML = `
            ${isSuccess === true ? '<i class="fas fa-check-circle"></i>' :
              isSuccess === false ? '<i class="fas fa-exclamation-circle"></i>' :
              '<i class="fas fa-sync fa-spin"></i>'}
            ${message}
        `;

        indicator.style.display = 'flex';
        indicator.style.background = isSuccess === true ? 'var(--success-color)' :
                                   isSuccess === false ? 'var(--danger-color)' :
                                   'var(--primary-color)';
    }

    hideSaveIndicator() {
        const indicator = document.getElementById('save-indicator');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    showError(message, error) {
        const container = document.getElementById('epg-mapping-container');
        if (container) {
            container.innerHTML = `
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <div>
                        <strong>${message}</strong>
                        <p>${this.escapeHtml(error.message || String(error))}</p>
                        <button class="btn btn-sm btn-primary" onclick="window.epgMappingManager.loadProviders()">
                            <i class="fas fa-redo"></i> Retry
                        </button>
                    </div>
                </div>
            `;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize when page loads - but don't load data yet
let epgMappingManager;

// Only create the manager instance, don't load data
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        epgMappingManager = new EPGMappingManager();
        window.epgMappingManager = epgMappingManager;
    });
} else {
    epgMappingManager = new EPGMappingManager();
    window.epgMappingManager = epgMappingManager;
}