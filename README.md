# Ultimate Backend (Kodi Add-on)

**Ultimate Backend** is a background service for **Kodi** that provides a local API for **live TV streaming**, **EPG data**, and **manifest management** from supported online TV providers.  

It acts as the **bridge between streaming services and Kodi’s PVR system**, designed specifically to work together with the official **[PVR IPTV Simple Client](https://github.com/kodi-pvr/pvr.iptvsimple)**.

---

## 🎯 Purpose

This add-on runs a small local web service inside Kodi.  
It:
- Logs in to supported streaming providers  
- Retrieves live channel lists and EPG data  
- Rewrites DASH manifests for Kodi playback  
- Generates M3U playlists compatible with PVR IPTV Simple  

Once configured, your live TV channels from streaming platforms appear directly in Kodi’s **TV** section — complete with EPG, logos, and DRM handling.

---

## 📺 Supported Providers

Currently supported:
- 🇩🇪 **Joyn (DE)**
- 🇦🇹 **Joyn (AT)**
- 🇨🇭 **Joyn (CH)**
- 🇪🇺 **RTL+**

More providers will be added in future versions.

---

## ✨ Key Features

- 📡 **Automatic Provider Integration** – Unified access to multiple streaming services  
- 🔁 **Manifest Proxying & Rewriting** – For seamless DASH playback via InputStream Adaptive  
- 🔐 **DRM Support** – Handles Widevine, PlayReady, and ClearKey license data  
- 🗓️ **EPG Data** – XMLTV-compatible program guide per provider  
- 🎵 **M3U Playlist Generation** – One-click generation for Kodi PVR clients  
- ⚡ **Caching System** – Caches manifests and playlists for fast reloads  
- 🌍 **Regional Support** – Separate configurations for Germany, Austria, and Switzerland  

---

## 🧩 Installation

1. Copy or clone this addon into your Kodi `addons` directory:
   ```
   ~/.kodi/addons/script.service.ultimate
   ```

2. Required dependencies (Kodi installs these automatically):
   - `xbmc.python` ≥ 3.0.0  
   - `script.module.bottle` ≥ 0.12.25  
   - `script.module.requests` ≥ 2.25.1  
   - `script.module.pycryptodome` ≥ 3.4.3  

3. Restart Kodi — the **Ultimate Backend** service starts automatically on login.

---

## ⚙️ Configuration

Go to:
> **Settings → Add-ons → Ultimate Backend → Configure**

### General Settings

| Setting | Description | Default |
|----------|--------------|----------|
| **Server Port** | Port of the local API | `7777` |
| **Default Country** | Default region (DE, AT, CH, EU) | `DE` |
| **API Key** | Optional global API key | *empty* |
| **Enable EPG Caching** | Cache EPG data locally | ✅ On |
| **Cache Duration (hours)** | Cache lifetime | `6` |

### Provider Settings

Each provider (Joyn DE/AT/CH, RTL+) can be configured individually:
- Enable or disable provider  
- Enter login credentials (username/password)  
- Configure proxy settings if needed (host and port)  

Example for Joyn (DE):
- Enable Joyn (DE)  
- Enter your credentials  
- Optionally enable and configure proxy  

---

## 🧠 Using with PVR IPTV Simple Client

The **Ultimate Backend** add-on is designed to work **together with**  
➡️ **[PVR IPTV Simple Client](https://github.com/kodi-pvr/pvr.iptvsimple)**

### Setup Steps

1. In Kodi, go to:  
   **Add-ons → My Add-ons → PVR Clients → PVR IPTV Simple Client → Configure**

2. Under **General → Location**, select:  
   🟢 *Remote Path (Internet address)*

3. Enter these URLs:

   **M3U Playlist URL:**
   ```
   http://localhost:7777/api/m3u
   ```

   **EPG XMLTV URL** (example for Joyn DE):
   ```
   http://localhost:7777/api/providers/joyn_de/epg
   ```

4. Save and restart Kodi’s PVR subsystem (or Kodi itself).  
   Your live TV channels and EPG will now appear in Kodi’s **TV** section.

💡 **Tip:**  
To regenerate and cache the latest M3U playlist manually, open this in your browser:  
```
http://localhost:7777/api/m3u/generate
```
This forces the backend to rebuild and cache the playlist for faster future loading.

---

## 🌐 API Overview

Once running, the addon exposes a local API:
```
http://localhost:7777/
```

### Common Endpoints

| Endpoint | Description |
|-----------|--------------|
| `/api/providers` | List all configured providers |
| `/api/providers/<provider>/channels` | Get available channels |
| `/api/providers/<provider>/channels/<id>/manifest` | Get or rewrite manifest |
| `/api/providers/<provider>/channels/<id>/stream` | Direct stream redirect |
| `/api/providers/<provider>/epg` | Get EPG in XMLTV format |
| `/api/m3u` | Cached combined playlist |
| `/api/m3u/generate` | Force regeneration and caching of playlist |
| `/api/cache/mpd/clear` | Clear MPD cache |
| `/api/cache/mpd/clear-expired` | Clear expired cache entries |

---

## 🧼 Cache Management

Ultimate Backend automatically caches:
- DASH Manifests  
- EPG Data  
- M3U Playlists  

### Manual cache actions:
| Purpose | URL |
|----------|-----|
| Clear all MPD cache | `/api/cache/mpd/clear` |
| Remove expired entries | `/api/cache/mpd/clear-expired` |
| Force M3U regeneration | `/api/m3u/generate` |
| Force provider-specific M3U regeneration | `/api/providers/<provider>/m3u/generate` |