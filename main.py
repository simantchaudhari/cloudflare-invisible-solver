import random
import re
from typing import List, Optional, Union

import structlog
from curl_cffi import requests

from utils.fingerprint import create_wb_result
from utils import constants

logger = structlog.get_logger()

# Regex to extract the 65-char encryption key from main.js
ENC_KEY_RE = re.compile(r'[a-zA-Z0-9+\-$]{65}')

# Regex to extract token components from the oneshot URL in main.js
# Format: /jsd/oneshot/{jsd}/{float}:{timestamp}:{token}/
# Token chars: alphanumeric, +, -, _, $ (varies per request)
ONESHOT_RE = re.compile(
    r'/jsd/oneshot/([a-f0-9]+)/(\d+\.\d+):(\d+):([a-zA-Z0-9+\-_$]+)/'
)


class CfSolver:
    def __init__(self, proxies: Optional[List[str]] = None) -> None:
        self.proxies = proxies

    def _create_session(self) -> requests.Session:
        session = requests.Session(
            impersonate="chrome146", headers=constants.DEFAULT_HEADERS.copy()
        )
        if self.proxies:
            proxy = "http://" + random.choice(self.proxies)
            session.proxies = {"http": proxy, "https": proxy}
        return session

    def get_solution(self, challenge_url: str) -> Union[bool, str]:
        session = self._create_session()
        challenge_website = challenge_url.split("/cdn-cgi/")[0]

        # Step 1: GET the challenge script URL — it 302-redirects to main.js
        # We need the cf-ray from the response headers, so don't follow redirects
        cloudflare_result = session.get(challenge_url, allow_redirects=False)
        cf_ray_id = cloudflare_result.headers["cf-ray"]
        cf_ray_id = cf_ray_id.split("-")[0]

        # The 302 redirect points to /cdn-cgi/challenge-platform/h/b/scripts/jsd/{jsd}/main.js
        # Extract jsd from the Location header
        location = cloudflare_result.headers.get("location", "")
        jsd_match = re.search(r'/jsd/([a-f0-9]+)/main\.js', location)
        if not jsd_match:
            logger.error("Could not extract jsd from redirect Location", location=location)
            return False
        jsd = jsd_match.group(1)

        # Step 2: GET the main.js to extract the encryption key and token components
        main_js_url = f"{challenge_website}{location}"
        main_js_response = session.get(main_js_url)
        main_js_text = main_js_response.text

        # Extract the 65-char encryption key
        cloudflare_enc_key = ENC_KEY_RE.search(main_js_text)
        if not cloudflare_enc_key:
            logger.error("Could not extract encryption key from main.js")
            return False
        cloudflare_enc_key = cloudflare_enc_key.group(0)

        # Extract token components from the oneshot URL in main.js
        oneshot_match = ONESHOT_RE.search(main_js_text)
        if not oneshot_match:
            logger.error("Could not extract oneshot token from main.js")
            return False
        token_jsd, token_float, token_timestamp, token_str = oneshot_match.groups()

        # Verify jsd matches (it should, since both come from the same CF deployment)
        if token_jsd != jsd:
            logger.warning("jsd mismatch", redirect_jsd=jsd, token_jsd=token_jsd)
            jsd = token_jsd

        # Step 3: Build the POST URL
        # Format: {site}/cdn-cgi/challenge-platform/h/b/jsd/oneshot/{jsd}/{float}:{timestamp}:{token}/{cf_ray}
        challenge_post_url = (
            f"{challenge_website}/cdn-cgi/challenge-platform/h/b/jsd/oneshot/"
            f"{jsd}/{token_float}:{token_timestamp}:{token_str}/{cf_ray_id}"
        )

        # Step 4: Generate the encoded payload
        wb_result = create_wb_result(
            session.headers["user-agent"],
            cloudflare_enc_key,
            challenge_website
        )

        logger.info(
            "Solving cloudflare challenge.",
            challenge_url=challenge_post_url[:60] + "...",
            encoded_payload=wb_result[:30] + "..",
        )

        # Step 5: POST the payload
        session.headers = constants.CHALLENGE_HEADERS.copy()
        session.headers["origin"] = challenge_website
        response = session.post(challenge_post_url, data=wb_result)

        if response.status_code == 200:
            logger.info(
                "Cloudflare challenge successfully solved.",
                cf_clearance=session.cookies["cf_clearance"][:50] + "..",
            )
            return session.cookies["cf_clearance"]
        logger.error("Error happened while solving cloudflare.", status=response.status_code)
        return False


if __name__ == "__main__":
    solver = CfSolver()
    result = solver.get_solution(
        "https://www.acehardware.com/cdn-cgi/challenge-platform/scripts/jsd/main.js"
    )
    print(f"\nResult: {result}")

    print("\n--- Testing discord.com ---")
    solver2 = CfSolver()
    result2 = solver2.get_solution(
        "https://discord.com/cdn-cgi/challenge-platform/scripts/jsd/main.js"
    )
    print(f"\nResult: {result2}")
