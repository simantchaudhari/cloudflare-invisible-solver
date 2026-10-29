import base64
import random
import re
from typing import List, Optional, Union
from urllib.parse import urlparse

import structlog
from curl_cffi import requests

from utils.fingerprint import create_wb_result
from utils import constants

logger = structlog.get_logger()


def _decode_cf_strings(main_js_text: str) -> dict:
    """
    Cloudflare's main.js obfuscates all string literals via a custom
    16-bit rotate-XOR cipher. This function reverse-engineers the cipher
    (seed + decoder function name) from the JS source, decrypts every
    call to that function, and returns a dict of interesting decoded values:
      - 'enc_key': the 65-char custom Base64 alphabet
      - 'oneshot_path': the /jsd/oneshot/... POST path
    """
    # Locate the decoder function name: var <name> = (function(...) { ... atob ... seed ... })
    dec_name_m = re.search(r'var\s+([a-zA-Z0-9_$]+)=\(function\(', main_js_text)
    if not dec_name_m:
        return {}
    dec_name = dec_name_m.group(1)

    # Locate the seed integer embedded after the atob call
    seed_m = re.search(r'\.atob\([a-zA-Z0-9_$]+\),[a-zA-Z0-9_$]+=(\d+)', main_js_text)
    if not seed_m:
        return {}
    seed_val = int(seed_m.group(1))

    def _decode_one(b64_str: str) -> str:
        data = base64.b64decode(b64_str)
        T = seed_val
        F = 0
        res = []
        while F < len(data):
            T = ((T << 8) | (T >> 8)) & 0xFFFF
            y = data[F] ^ (T >> 8)
            F += 1
            if y == 255:
                T = ((T << 8) | (T >> 8)) & 0xFFFF
                y = data[F] ^ (T >> 8)
                F += 1
                T = ((T << 8) | (T >> 8)) & 0xFFFF
                y |= (data[F] ^ (T >> 8)) << 8
                F += 1
            res.append(chr(y))
        return ''.join(res)

    # Find all encoded string calls: decFunc(`...`) or decFunc('...')
    cipher_calls = re.findall(
        r'\b' + re.escape(dec_name) + r'\([`\'"]([^`\'"]+)[`\'"]\)',
        main_js_text
    )

    result = {}
    for cipher in cipher_calls:
        try:
            plain = _decode_one(cipher)
            # 65-char custom Base64 alphabet
            if len(plain) == 65 and re.match(r'^[a-zA-Z0-9+\-$]{65}$', plain):
                result['enc_key'] = plain
            # oneshot POST endpoint path
            elif '/jsd/oneshot/' in plain:
                result['oneshot_path'] = plain
        except Exception:
            pass

    return result


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
        parsed = urlparse(challenge_url)
        challenge_website = f"{parsed.scheme}://{parsed.netloc}"

        # Step 1: GET challenge URL — 302 redirects to versioned main.js
        # Do NOT follow redirect; we need cf-ray + location headers
        cloudflare_result = session.get(challenge_url, allow_redirects=False)
        if "cf-ray" not in cloudflare_result.headers:
            logger.error("Missing cf-ray header", status=cloudflare_result.status_code)
            return False

        cf_ray_id = cloudflare_result.headers["cf-ray"].split("-")[0]
        location = cloudflare_result.headers.get("location", "")

        # Extract challenge mode (h/g or h/b) from redirect location
        mode_m = re.search(r'/challenge-platform/h/([a-z])/', location)
        mode = mode_m.group(1) if mode_m else "g"

        if not location:
            logger.error("Missing Location header in 302 response")
            return False

        # Step 2: GET the versioned main.js
        main_js_url = f"{challenge_website}{location}"
        main_js_response = session.get(main_js_url)
        main_js_text = main_js_response.text

        # Step 3: Dynamically decode obfuscated strings from main.js
        decoded = _decode_cf_strings(main_js_text)
        cloudflare_enc_key = decoded.get('enc_key')
        oneshot_path = decoded.get('oneshot_path')

        if not cloudflare_enc_key:
            logger.error("Could not extract encryption key from main.js")
            return False
        if not oneshot_path:
            logger.error("Could not extract oneshot path from main.js")
            return False

        if not oneshot_path.endswith('/'):
            oneshot_path += '/'

        # Step 4: Build POST URL
        # Format: {site}/cdn-cgi/challenge-platform/h/{mode}{oneshot_path}{cf_ray}
        challenge_post_url = (
            f"{challenge_website}/cdn-cgi/challenge-platform/h/{mode}"
            f"{oneshot_path}{cf_ray_id}"
        )

        # Step 5: Generate the encoded fingerprint payload
        wb_result = create_wb_result(
            session.headers["user-agent"],
            cloudflare_enc_key,
            challenge_website
        )

        logger.info(
            "Solving cloudflare challenge.",
            challenge_url=challenge_post_url[:70] + "...",
            encoded_payload=wb_result[:30] + "..",
        )

        # Step 6: POST the payload
        session.headers = constants.CHALLENGE_HEADERS.copy()
        session.headers["origin"] = challenge_website
        response = session.post(challenge_post_url, data=wb_result)

        if response.status_code == 200:
            cf_clearance = session.cookies.get("cf_clearance")
            if not cf_clearance:
                logger.error("POST succeeded but cf_clearance cookie not found")
                return False
            logger.info(
                "Cloudflare challenge successfully solved.",
                cf_clearance=cf_clearance[:50] + "..",
            )
            return cf_clearance

        logger.error(
            "Error happened while solving cloudflare.",
            status=response.status_code,
            body=response.text[:200],
        )
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
