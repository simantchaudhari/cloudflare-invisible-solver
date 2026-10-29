import re
from typing import List, Optional
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory
from curl_cffi import requests as cf_requests

from main import CfSolver, _decode_cf_strings
from utils import constants

app = Flask(__name__, static_folder="static")

CF_BM_RE = re.compile(r'__cf_bm=([^;,\s]+)')


class CfSolverAPI(CfSolver):
    """Extended solver that returns full details: clearance, __cf_bm, user-agent."""

    def get_solution_full(self, challenge_url: str) -> dict:
        from utils.fingerprint import create_wb_result

        session = self._create_session()
        user_agent = session.headers["user-agent"]

        parsed = urlparse(challenge_url)
        challenge_website = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: GET challenge URL (no redirect follow)
        try:
            cloudflare_result = session.get(challenge_url, allow_redirects=False)
        except Exception as e:
            return {"success": False, "error": f"Network error on initial GET: {e}"}

        if "cf-ray" not in cloudflare_result.headers:
            return {
                "success": False,
                "error": f"No cf-ray header (status {cloudflare_result.status_code}). "
                         "This URL may not serve the invisible challenge."
            }

        cf_ray_id = cloudflare_result.headers["cf-ray"].split("-")[0]
        location = cloudflare_result.headers.get("location", "")

        # Parse __cf_bm from Set-Cookie on the 302 response (some sites set it here)
        cf_bm = ""
        for hdr_name, hdr_val in cloudflare_result.headers.items():
            if hdr_name.lower() == "set-cookie":
                m = CF_BM_RE.search(hdr_val)
                if m:
                    cf_bm = m.group(1)

        # Extract challenge mode from redirect path
        mode_m = re.search(r'/challenge-platform/h/([a-z])/', location)
        mode = mode_m.group(1) if mode_m else "g"

        if not location:
            return {"success": False, "error": "Missing Location header in 302 redirect"}

        # Step 2: GET main.js
        main_js_url = f"{challenge_website}{location}"
        try:
            main_js_response = session.get(main_js_url)
        except Exception as e:
            return {"success": False, "error": f"Network error fetching main.js: {e}"}

        main_js_text = main_js_response.text

        # Step 3: Dynamically decode obfuscated strings
        decoded = _decode_cf_strings(main_js_text)
        cloudflare_enc_key = decoded.get('enc_key')
        oneshot_path = decoded.get('oneshot_path')

        if not cloudflare_enc_key:
            return {"success": False, "error": "Could not extract encryption key from main.js"}
        if not oneshot_path:
            return {"success": False, "error": "Could not extract oneshot path from main.js"}

        if not oneshot_path.endswith('/'):
            oneshot_path += '/'

        # Step 4: Build POST URL
        challenge_post_url = (
            f"{challenge_website}/cdn-cgi/challenge-platform/h/{mode}"
            f"{oneshot_path}{cf_ray_id}"
        )

        # Step 5: Generate encoded payload
        wb_result = create_wb_result(user_agent, cloudflare_enc_key, challenge_website)

        # Step 6: POST payload
        post_headers = constants.CHALLENGE_HEADERS.copy()
        post_headers["origin"] = challenge_website
        session.headers = post_headers

        try:
            response = session.post(challenge_post_url, data=wb_result)
        except Exception as e:
            return {"success": False, "error": f"Network error on POST: {e}"}

        if response.status_code == 200:
            # Try to get __cf_bm from POST response headers
            for hdr_name, hdr_val in response.headers.items():
                if hdr_name.lower() == "set-cookie":
                    m = CF_BM_RE.search(hdr_val)
                    if m:
                        cf_bm = m.group(1)

            if not cf_bm:
                cf_bm = session.cookies.get("__cf_bm", "")

            cf_clearance = session.cookies.get("cf_clearance", "")
            if not cf_clearance:
                return {
                    "success": False,
                    "error": "POST returned 200 but no cf_clearance cookie was set"
                }

            return {
                "success": True,
                "cf_clearance": cf_clearance,
                "__cf_bm": cf_bm,
                "user_agent": user_agent,
            }

        return {
            "success": False,
            "error": f"POST returned status {response.status_code}: {response.text[:300]}"
        }


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/solve")
def solve():
    """Solve a Cloudflare invisible challenge.

    GET /solve?url=https://example.com/cdn-cgi/challenge-platform/scripts/jsd/main.js
    Optional: &proxies=ip:port,ip:port
    """
    url = request.args.get("url")
    if not url:
        return jsonify({"success": False, "error": "Missing 'url' parameter"}), 400

    proxies_param = request.args.get("proxies")
    proxies: Optional[List[str]] = None
    if proxies_param:
        proxies = [p.strip() for p in proxies_param.split(",") if p.strip()]

    # Create a fresh solver per request (no shared mutable state)
    solver = CfSolverAPI(proxies=proxies)
    result = solver.get_solution_full(url)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
