import sys
import os
from flask import Flask, request, jsonify

# Add the project root directory to sys.path to resolve downloader module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from downloader import resolve_link

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "TeraBridge API is running!",
        "endpoints": {
            "/api/resolve": "GET or POST to resolve share links"
        }
    })

@app.route("/api/resolve", methods=["GET", "POST"])
def resolve():
    # 1. Parse parameters
    link = ""
    action = "d"  # default is download
    wait_for_transcoding = False

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        link = data.get("url") or data.get("link") or ""
        action = data.get("mode") or data.get("action") or "d"
        wait_for_transcoding = bool(data.get("wait"))
    else:
        link = request.args.get("url") or request.args.get("link") or ""
        action = request.args.get("mode") or request.args.get("action") or "d"
        wait_for_transcoding = request.args.get("wait") in ("true", "1", "True")

    if not link:
        return jsonify({
            "status": "error",
            "message": "Missing required parameter 'url' or 'link'."
        }), 400

    # Ensure action code matches downloader expected format ('d', 's', or 'l')
    act_lower = action.lower()
    if act_lower in ("s", "stream", "streaming"):
        action = "s"
    elif act_lower in ("l", "list", "info", "metadata"):
        action = "l"
    else:
        action = "d"

    # 2. Call resolve_link from downloader
    try:
        res = resolve_link(link, action=action, wait_for_transcoding=wait_for_transcoding)
        if res.get("errno") != 0:
            return jsonify({
                "status": "error",
                "message": res.get("error", "Unknown resolution error occurred.")
            }), 400

        # Check if any video has transcoding in progress
        is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in res.get("files", []))
        
        response_data = {
            "status": "transcoding" if is_transcoding else "success",
            "title": res.get("title"),
            "share_id": res.get("share_id"),
            "uk": res.get("uk"),
            "files": []
        }

        for f in res.get("files", []):
            file_info = {
                "filename": f.get("filename"),
                "size_bytes": f.get("size_bytes"),
                "size_mb": f.get("size_mb"),
                "fs_id": f.get("fs_id"),
                "transfer_status": f.get("transfer_status"),
                "dlink": f.get("dlink"),
                "stream_ready": f.get("stream_ready"),
                "error": f.get("error")
            }
            # Only include HLS stream content if it is successfully parsed
            if f.get("stream_ready"):
                file_info["stream_m3u8"] = f.get("stream_m3u8")
            response_data["files"].append(file_info)

        return jsonify(response_data)

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Server encountered exception: {str(e)}"
        }), 500

# Standalone execution wrapper for local testing
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
