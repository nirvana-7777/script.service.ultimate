# Ultimate Backend (Kodi Add-on)

**Ultimate Backend** is a background service for **Kodi** that provides a local API for **live TV streaming**, **EPG data**, and **manifest management** from supported online TV providers.

It act as the **bridge between streaming services and Kodi's PVR system**, designed specifically to work together with the official **PVR IPTV Simple Client**.

---

## 🎯 Purpose

This add-on runs a small local web service inside Kodi.
It:
- Logs in to supported streaming providers
- Retrieves live channel lists and EPG data
- Rewrites DASH manifests for Kodi playback
- Generates M3U playlists compatible with PVR IPTV Simple

Once configured, your live TV channels from streaming platforms appear directly in Kodi's **TV** section — complete with EPG, logos, and DRM handling.

---

## 📺 Supported Providers

Currently supported:

- 🇩🇪 **Joyn (DE)**
- 🇦🇹 **Joyn (AT)**
- 🇨🇭 **Joyn (CH)**
- 🇩🇪 **RTL+**
- 🇩🇪 **Magenta TV 2.0**
- 🇦🇹 **Magenta TV (AT)**
- 🇭🇷 **Max TV (HR)**
- 🇭🇷 **HRTi (HR)**
- 🇵🇱 **Magenta TV (PL)**
- 🇲🇪 **Magenta TV (ME)**
- 🇭🇺 **Magenta TV (HU)**

More providers will be added in future versions.


---

## ✨ Key Features

- 📡 **Automatic Provider Integration** – Unified access to multiple streaming services
- 🔁 **Manifest Proxying & Rewriting** – For seamless DASH playback via InputStream Adaptive
- 🔐 **DRM Support** – Handles Widevine, PlayReady, and ClearKey license data
- 🗓️ **EPG Data** – XMLTV-compatible program guide per provider (coming in future version)
- 🎵 **M3U Playlist Generation** – Individual playlists for each provider
- ⚡ **Caching System** – Caches manifests and playlists for fast reloads
- 🌍 **Regional Support** – Separate configurations for Germany, Austria, and Switzerland
- 🔄 **Provider-Specific Proxy** – Configure proxy settings individually for each provider

---

## 🧩 Installation

1. Copy or clone this addon into your Kodi `addons` directory:
   ~/.kodi/addons/script.service.ultimate

2. Required dependencies (Kodi installs these automatically):
   - `xbmc.python` ≥ 3.0.0
   - `script.module.bottle` ≥ 0.12.25
   - `script.module.requests` ≥ 2.25.1
   - `script.module.pycryptodome` ≥ 3.4.3

3. Restart Kodi — the **Ultimate Backend** service starts automatically on login.

---

## ⚙️ Configuration

Go to:
**Settings → Add-ons → Ultimate Backend → Configure**

### General Settings

| Setting | Description | Default |
|----------|--------------|----------|
| **Server Port** | Port of the local API | `7777` |
| **Default Country** | Default region (DE, AT, CH, EU) | `DE` |
| **API Key** | Optional global API key | *empty* |
| **Enable EPG Caching** | Cache EPG data locally | ✅ On |
| **Cache Duration (hours)** | Cache lifetime | `6` |

### Provider Configuration

**Each provider can be individually enabled and configured:**

#### Joyn Providers (DE/AT/CH)
- **Enable Provider** – Toggle on/off for each country
- **Credentials** – Enter your username and password
- **Proxy Settings** – Optional proxy configuration per provider:
  - Enable proxy support
  - Set proxy host and port
  - Useful for geo-restricted content or network requirements

#### RTL+ Provider
- **Credentials** – Enter your RTL+ username and password
- **Proxy Settings** – Optional proxy configuration:
  - Enable proxy if needed for your region
  - Configure proxy host and port

**💡 Recommendation:** Configure only the providers you actually use to improve performance and reduce startup time.

---

## 🧠 Using with PVR IPTV Simple Client

The **Ultimate Backend** add-on is designed to work **together with PVR IPTV Simple Client**

### Setup Steps

1. In Kodi, go to:
   **Add-ons → My Add-ons → PVR Clients → PVR IPTV Simple Client → Configure**

2. Under **General → Location**, select:
   🟢 *Remote Path (Internet address)*

3. **Recommended:** Use provider-specific M3U URLs for better performance and organization:

   **For Joyn DE:**
   M3U Playlist URL: http://localhost:7777/api/providers/joyn_de/m3u
   EPG XMLTV URL: http://localhost:7777/api/providers/joyn_de/epg

   **For Joyn AT:**
   M3U Playlist URL: http://localhost:7777/api/providers/joyn_at/m3u
   EPG XMLTV URL: http://localhost:7777/api/providers/joyn_at/epg

   **For RTL+:**
   M3U Playlist URL: http://localhost:7777/api/providers/rtlplus/m3u
   EPG XMLTV URL: http://localhost:7777/api/providers/rtlplus/epg

   *Alternatively, you can use the combined playlist (not recommended for multiple providers):*
   M3U Playlist URL: http://localhost:7777/api/m3u

4. Save and restart Kodi's PVR subsystem (or Kodi itself).
   Your live TV channels will now appear in Kodi's **TV** section.

⚠️ **Note:** EPG (Electronic Program Guide) data will be available in a future version. Currently, channels will be displayed without program information.

💡 **Tip:**
To regenerate and cache the latest M3U playlist manually, open these URLs in your browser:
- Provider-specific: http://localhost:7777/api/providers/joyn_de/m3u/generate
- All providers: http://localhost:7777/api/m3u/generate

This forces the backend to rebuild and cache the playlist for faster future loading.

---

## 🌐 API Overview

Once running, the addon exposes a local API:
http://localhost:7777/

### Common Endpoints

| Endpoint | Description |
|-----------|--------------|
| `/api/providers` | List all configured providers |
| `/api/providers/<provider>/channels` | Get available channels |
| `/api/providers/<provider>/channels/<id>/manifest` | Get or rewrite manifest |
| `/api/providers/<provider>/channels/<id>/stream` | Direct stream redirect |
| `/api/providers/<provider>/epg` | Get EPG in XMLTV format (future version) |
| `/api/providers/<provider>/m3u` | **Recommended:** Provider-specific cached playlist |
| `/api/m3u` | Combined playlist (all providers) |
| `/api/providers/<provider>/m3u/generate` | Force regeneration of provider-specific playlist |
| `/api/m3u/generate` | Force regeneration of combined playlist |
| `/api/cache/mpd/clear` | Clear MPD cache |
| `/api/cache/mpd/clear-expired` | Clear expired cache entries |

---

## 🧼 Cache Management

Ultimate Backend automatically caches:
- DASH Manifests
- EPG Data (when available in future version)
- M3U Playlists (both provider-specific and combined)

### Manual cache actions:
| Purpose | URL |
|----------|-----|
| Clear all MPD cache | `/api/cache/mpd/clear` |
| Remove expired entries | `/api/cache/mpd/clear-expired` |
| Force provider M3U regeneration | `/api/providers/<provider>/m3u/generate` |
| Force all M3U regeneration | `/api/m3u/generate` |

---

## 🆕 Coming Soon

- **EPG Support**: Full Electronic Program Guide data for all channels
- **More Providers**: Additional streaming services
- **Enhanced Caching**: Improved cache management and performance
- **Advanced Settings**: More configuration options for power users

Stay tuned for updates!

---

## 🕒 Catchup & EPG Support (Now Available)

Ultimate Backend now includes **fully working Catchup TV and EPG support**.

### 🕒 Catchup TV
- Provider-based catchup windows (hours configurable per provider)
- Seamless playback via the same stream endpoint
- Works transparently with Kodi PVR IPTV Simple Client
- Automatic validation to ensure playback stays within allowed catchup ranges

### 🗓️ EPG (Electronic Program Guide)
- Live EPG data support is now enabled
- XMLTV-compatible output
- Per-provider EPG endpoints
- Supports external EPG sources via URL

### 🧩 EPG Channel Mapping
- Built-in **EPG mapping interface**
- Fuzzy matching to map provider channels to EPG channels
- Manual override and fine-tuning via web UI
- Mapping is persisted and reused automatically

Access the web UI at:
http://localhost:7777/

---

## 🐳 Docker Support

Ultimate Backend can be run **fully standalone using Docker**.

### docker-compose.yml

```yaml
version: '3.8'

services:
  ultimate-backend:
    build:
      context: .
      args:
        - USER_ID=1000
        - GROUP_ID=1000
    image: nirvana777/ultimate-backend:latest
    container_name: ultimate-backend
    restart: unless-stopped
    ports:
      - "7777:7777"
    environment:
      - ULTIMATE_PORT=7777
      - ULTIMATE_DEBUG=false
      - ULTIMATE_EPG_URL=https://raw.githubusercontent.com/epgshare01/share01/master/epg.xml.gz
      - TZ=${TZ:-Europe/Berlin}
    volumes:
      - ./config:/config
      - ./logs:/logs
      - ./cache:/cache
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7777/api/providers"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    networks:
      - ultimate-network
    
networks:
  ultimate-network:
    driver: bridge
```

### 🚀 Docker Notes
- Perfect for **NAS, servers, and headless setups**
- No Kodi installation required
- Web UI, API, M3U, EPG, and Catchup all work identically

---