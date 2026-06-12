# TeraBridge API

This repository contains a lightweight, modular Python CLI utility and a Flask API designed for retrieving direct download links and playable HLS `.m3u8` streaming manifests from Terabox shared folders. It is configured to run locally or as a Serverless Function on **Vercel**.

---

## Features

- **Dynamic Token Resolution:** Automatically resolves session-specific `bdstoken` and `jsToken` dynamically from your cookies to bypass standard verification blocks.
- **Save Location Targeting:** Copies shared files automatically to a `/cloudvids` folder inside the account storage for clear organization.
- **HLS Transcoding Handling:** Automatically handles transcoding ready delays (`errno: 130`). For serverless executions, it flags this state cleanly in the JSON response, enabling clients to poll/retry.
- **Vercel Deployable:** Designed out-of-the-box for quick deployment using the Vercel Python runtime.

---

## Project Structure

```
terabridge-api/
├── api/
│   └── index.py        # Flask API router (Serverless handler)
├── downloader.py       # Core library & CLI interface
├── README.md           # This documentation
├── requirements.txt    # Python packaging dependencies
└── vercel.json         # Vercel deployment rewrites config
```

---

## 1. Local CLI Usage

Run the core script as a Command Line Interface (CLI):

```bash
# 1. Run direct download mode
python downloader.py "<terabox_share_link>"

# 2. Run streaming manifest resolver mode
python downloader.py --stream "<terabox_share_link>"
```

*Note: If no link is provided as an argument, the CLI will prompt for one interactively.*

---

## 2. Local Flask API Testing

Run the Flask server locally:

```bash
# Install dependencies
pip install -r requirements.txt

# Start the local development server (port 5000)
python api/index.py
```

### Endpoints

#### **GET /api/resolve**
Resolves Terabox share links dynamically.

**Parameters:**
- `url` (Required): The full Terabox share URL.
- `mode` (Optional): Either `download` (default) or `stream`.
- `wait` (Optional): Set to `true` or `1` if you want the API to block and retry if transcoding is in progress. Recommended to leave `false` for serverless hosting to avoid timeouts.

**Example Request:**
```
GET http://127.0.0.1:5000/api/resolve?url=https://terasharelink.com/s/1LBCiS-QC7WtAR4OolsC2pQ&mode=download
```

**Example JSON Response:**
```json
{
  "status": "success",
  "title": "/2026-06-10 18-20/VID_20231007175038.mp4",
  "share_id": 4289361191,
  "uk": 4399686012242,
  "files": [
    {
      "filename": "VID_20231007175038.mp4",
      "size_bytes": 7514979,
      "size_mb": 7.17,
      "fs_id": "937887385083215",
      "transfer_status": "success",
      "dlink": "https://dm-d.terabox.com/file/a8050382588a965fcdf39e10ef48b6ee?fid=...",
      "stream_ready": false,
      "error": null
    }
  ]
}
```

---

## 3. Vercel Deployment

Deploy the API globally to Vercel in seconds:

1. Install the Vercel CLI: `npm i -g vercel`
2. Navigate into the folder: `cd terabridge-api`
3. Run: `vercel`
