import re
from typing import List, Optional

from flask import Flask, jsonify, request
from curl_cffi import requests

from main import CfSolver
from utils import constants

app = Flask(__name__)

ENC_KEY_RE = re.compile(r'[a-zA-Z0-9+\-$]{65}')
ONESHOT_RE = re.compile(
    r'/jsd/oneshot/([a-f0-9]+)/(\d+\.\d+):(\d+):([a-zA-Z0-9+\-_$]+)/'
)
CF_BM_RE = re.compile(r'__cf_bm=([^;]+)')


class CfSolverAPI(CfSolver):
    """Extended solver that returns full details including user-agent."""

    def get_solution_full(self, challenge_url: str) -> dict:
        session = self._create_session()
        user_agent = session.headers["user-agent"]
        challenge_website = challenge_url.split("/cdn-cgi/")[0]

        cloudflare_result = session.get(challenge_url, allow_redirects=False)
        cf_ray_id = cloudflare_result.headers["cf-ray"].split("-")[0]

        # Parse __cf_bm from the 302 response Set-Cookie header
        cf_bm = ""
        set_cookie_302 = cloudflare_result.headers.get("set-cookie", "")
        cf_bm_match = CF_BM_RE.search(set_cookie_302)
        if cf_bm_match:
            cf_bm = cf_bm_match.group(1)

        location = cloudflare_result.headers.get("location", "")
        jsd_match = re.search(r'/jsd/([a-f0-9]+)/main\.js', location)
        if not jsd_match:
            return {"success": False, "error": "Could not extract jsd from redirect"}
        jsd = jsd_match.group(1)

        main_js_url = f"{challenge_website}{location}"
        main_js_response = session.get(main_js_url)
        main_js_text = main_js_response.text

        cloudflare_enc_key = ENC_KEY_RE.search(main_js_text)
        if not cloudflare_enc_key:
            return {"success": False, "error": "Could not extract encryption key"}
        cloudflare_enc_key = cloudflare_enc_key.group(0)

        oneshot_match = ONESHOT_RE.search(main_js_text)
        if not oneshot_match:
            return {"success": False, "error": "Could not extract oneshot token"}
        token_jsd, token_float, token_timestamp, token_str = oneshot_match.groups()

        if token_jsd != jsd:
            jsd = token_jsd

        challenge_post_url = (
            f"{challenge_website}/cdn-cgi/challenge-platform/h/b/jsd/oneshot/"
            f"{jsd}/{token_float}:{token_timestamp}:{token_str}/{cf_ray_id}"
        )

        from utils.fingerprint import create_wb_result
        wb_result = create_wb_result(user_agent, cloudflare_enc_key, challenge_website)

        session.headers = constants.CHALLENGE_HEADERS.copy()
        session.headers["origin"] = challenge_website
        response = session.post(challenge_post_url, data=wb_result)

        if response.status_code == 200:
            # Also try parsing __cf_bm from the POST response Set-Cookie
            set_cookie_post = response.headers.get("set-cookie", "")
            cf_bm_post_match = CF_BM_RE.search(set_cookie_post)
            if cf_bm_post_match:
                cf_bm = cf_bm_post_match.group(1)
            elif not cf_bm:
                cf_bm = session.cookies.get("__cf_bm", "")
            return {
                "success": True,
                "cf_clearance": session.cookies["cf_clearance"],
                "__cf_bm": cf_bm,
                "user_agent": user_agent,
            }
        return {"success": False, "error": f"POST returned status {response.status_code}"}


solver = CfSolverAPI()


@app.route("/solve")
def solve():
    """Solve a Cloudflare invisible challenge.

    Usage: GET /solve?url=https://example.com/cdn-cgi/challenge-platform/scripts/jsd/main.js
    Optional: &proxies=ip:port,ip:port
    """
    url = request.args.get("url")
    if not url:
        return jsonify({"success": False, "error": "Missing 'url' parameter"}), 400

    proxies_param = request.args.get("proxies")
    if proxies_param:
        proxies = [p.strip() for p in proxies_param.split(",") if p.strip()]
        solver.proxies = proxies
    else:
        solver.proxies = None

    result = solver.get_solution_full(url)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
