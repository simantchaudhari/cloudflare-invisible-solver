# cloudflare-invisible-solver

cloned from https://github.com/notemrovsky/cloudflare-invisible-solver — full credit to the original author. this is a modified fork with updated challenge flow handling, a flask api server, and chrome146 tls impersonation.

solves the cloudflare invisible challenge (the jsd/oneshot one, not the managed turnstile one) and gives you back the cf_clearance and __cf_bm cookies.

this only works on sites that use the invisible challenge flow. if the site upgraded to managed challenge (cType: 'managed' with the turnstile widget) this wont help you there. discord, stockx, and other sites that still use the invisible flow work fine.

## how it works

cloudflare serves a 302 redirect to a main.js file. that js has a 65-char encryption key and a oneshot token embedded in it. the solver:

1. GETs the challenge url (follows the 302, grabs cf-ray from headers)
2. extracts jsd from the redirect location
3. GETs main.js, pulls out the 65-char enc key + the oneshot token (float:timestamp:token)
4. builds a fingerprint payload (browser props, navigator, screen, dom stuff)
5. encodes it: json stringify -> deflate compress -> 3-byte header -> xor encrypt (fnv1a seeded xorshift32) -> custom base64 with the 65-char key as alphabet
6. POSTs the encoded payload to /jsd/oneshot/{jsd}/{token}/{cf_ray}
7. gets cf_clearance + __cf_bm back in the cookies

the encoding pipeline was reversed from the obfuscated main.js. the fingerprint dict is a big collection of browser properties that cloudflare checks to make sure you look like a real browser.

## install

```
pip install -r requirements.txt
```

you need curl_cffi for the tls impersonation (chrome146 fingerprint). structlog for logging. flask if you want the api server.

## usage

### as a script

```python
from main import CfSolver

solver = CfSolver()
result = solver.get_solution(
    "https://discord.com/cdn-cgi/challenge-platform/scripts/jsd/main.js"
)
print(result)  # cf_clearance cookie string
```

### as an api server

```
python server.py
```

then:

```
GET http://localhost:5000/solve?url=https://discord.com/cdn-cgi/challenge-platform/scripts/jsd/main.js
```

response:

```json
{
  "success": true,
  "cf_clearance": "B8xnvfdK.EIxrhYEnNbqH8Uv...",
  "__cf_bm": "CM3WBMw2iwuf7.s2NybSTjttGUs...",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
}
```

with proxies:

```
GET http://localhost:5000/solve?url=<url>&proxies=1.2.3.4:8080,5.6.7.8:8080
```

## important stuff

- the user-agent matters. cf ties the cf_clearance cookie to the ua. if you solve with chrome146 and then try to use the cookies with a different ua youll get 403. use the same ua the solver returns.
- curl_cffi 0.15 maxes out at chrome146 impersonation. if you need higher you gotta wait for an update or use a different tls lib.
- __cf_bm isnt always set. some sites only give you cf_clearance. the api returns empty string for __cf_bm in that case.
- the challenge url format is: `https://<site>/cdn-cgi/challenge-platform/scripts/jsd/main.js`

## what this does NOT do

- does not solve managed challenges (turnstile). if the site has cType: 'managed' in the challenge html, this solver wont work. you need a turnstile solver for that.
- does not solve recaptcha or any other captcha.
- does not handle sites that require additional tokens (like acehardware login which needs both recaptcha + turnstile tokens in the post body).

## files

- `main.py` - the solver class, does the full challenge flow
- `server.py` - flask api wrapper around the solver
- `utils/encryption.py` - the encode pipeline (deflate + xor + custom base64)
- `utils/fingerprint.py` - builds the browser fingerprint payload
- `utils/constants.py` - headers and regex patterns

## tested on

- discord.com - works
- stockx.com - works
- acehardware.com - the homepage invisible challenge works but the login page upgraded to managed challenge (turnstile), so cookies alone wont get you into the login

---

⚠️ **this is for educational purposes only.** im sharing this for learning and research. dont use it to bypass cloudflare on sites you dont own or dont have permission to test. respect the sites protections and their terms of service.
