import re
import time
import json
import random
import threading
import requests
import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CAPTCHA_TYPES = {
    "recaptcha_v2": "reCAPTCHA v2",
    "recaptcha_v3": "reCAPTCHA v3",
    "hcaptcha": "hCaptcha",
    "turnstile": "Cloudflare Turnstile",
}

PROVIDERS = {
    "capsolver": {
        "base_url": "https://api.capsolver.com",
        "create_task": "/createTask",
        "get_result": "/getTaskResult",
    },
    "2captcha": {
        "base_url": "https://api.2captcha.com",
        "create_task": "/createTask",
        "get_result": "/getTaskResult",
    },
    "anticaptcha": {
        "base_url": "https://api.anti-captcha.com",
        "create_task": "/createTask",
        "get_result": "/getTaskResult",
    },
}

_BYPASS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.92 Safari/537.36",
]

# curl_cffi impersonation profiles to cycle through
_CURL_PROFILES = [
    "chrome110", "chrome107", "chrome104", "chrome101",
    "chrome120", "chrome116", "chrome99",
    "safari15_5", "safari17_0",
]

_CF_CHALLENGE_SIGNALS = [
    "just a moment", "checking your browser", "verify you are human",
    "cloudflare", "cf-chl-bypass", "ray id", "ddos protection",
    "please wait", "enable javascript and cookies",
    "challenge-platform", "cf-please-wait",
]

_SITEKEY_PATTERNS = {
    "recaptcha": [
        r'data-sitekey=["\']([A-Za-z0-9_-]{40})["\']',
        r'grecaptcha\.render\([^,]+,\s*\{[^}]*sitekey["\s:]+["\']([A-Za-z0-9_-]{40})["\']',
        r'recaptcha/api\.js\?render=([A-Za-z0-9_-]{40})',
        r'sitekey:\s*["\']([A-Za-z0-9_-]{40})["\']',
        r'recaptchaSiteKey["\s:]+["\']([A-Za-z0-9_-]{40})["\']',
    ],
    "hcaptcha": [
        r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
        r'hcaptcha\.render\([^,]+,\s*\{[^}]*sitekey["\s:]+["\']([0-9a-f-]{36})["\']',
        r'sitekey:\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
    ],
    "turnstile": [
        r'data-sitekey=["\']([0-9a-zA-Z_-]{20,})["\']',
        r"data-sitekey='([0-9a-zA-Z_-]{20,})'",
        r'turnstile\.render\([^,]+,\s*\{[^}]*sitekey["\s:]+["\']([0-9a-zA-Z_-]{20,})["\']',
        r'cf-turnstile["\'][^>]*data-sitekey=["\']([^"\']+)["\']',
        r'"sitekey"\s*:\s*"(0x[0-9a-zA-Z_-]+)"',
        r"'sitekey'\s*:\s*'(0x[0-9a-zA-Z_-]+)'",
        r'sitekey["\s:=]+["\']?(0x[A-Za-z0-9_-]{20,})["\']?',
        r'chlApiSitekey["\s:]+["\']([0-9a-zA-Z_-]{20,})["\']',
        r'turnstileKey["\s:]+["\']([0-9a-zA-Z_-]{20,})["\']',
        r'data-cdata=["\']([^"\']+)["\']',
    ],
}

_CAPTCHA_DETECT_PATTERNS = {
    "recaptcha_v2": [
        r'class=["\']g-recaptcha["\']',
        r'grecaptcha\.render',
        r'recaptcha/api\.js(?!\?render=)',
        r'g-recaptcha-response',
    ],
    "recaptcha_v3": [
        r'recaptcha/api\.js\?render=',
        r'grecaptcha\.execute',
        r'recaptcha.*v3',
        r'recaptchaV3',
    ],
    "hcaptcha": [
        r'class=["\']h-captcha["\']',
        r'hcaptcha\.com/1/api\.js',
        r'h-captcha-response',
        r'hcaptcha\.render',
    ],
    "turnstile": [
        r'cf-turnstile',
        r'challenges\.cloudflare\.com/turnstile',
        r'cf-turnstile-response',
        r'turnstile\.render',
        r'turnstile/v0/api\.js',
    ],
}

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

_stats = {
    "detected": 0,
    "solved": 0,
    "failed": 0,
    "bypassed": 0,
    "total_time": 0.0,
    "by_type": {},
    "by_method": {},
}


def get_solver_stats():
    return _stats.copy()


def reset_solver_stats():
    global _stats
    _stats = {
        "detected": 0, "solved": 0, "failed": 0, "bypassed": 0,
        "total_time": 0.0, "by_type": {}, "by_method": {},
    }


def _record_bypass(method, captcha_type="unknown"):
    _stats["bypassed"] += 1
    _stats["by_type"][captcha_type] = _stats["by_type"].get(captcha_type, 0) + 1
    _stats["by_method"][method] = _stats["by_method"].get(method, 0) + 1


# ---------------------------------------------------------------------------
# cf_clearance cookie cache  (per-domain, 1-hour TTL)
# ---------------------------------------------------------------------------

_clearance_cache: dict = {}
_clearance_lock = threading.Lock()
_CLEARANCE_TTL = 3600


def _get_clearance_cache(domain: str):
    with _clearance_lock:
        entry = _clearance_cache.get(domain)
        if entry and time.time() - entry["ts"] < _CLEARANCE_TTL:
            return entry["cookies"]
        if entry:
            del _clearance_cache[domain]
    return None


def _set_clearance_cache(domain: str, cookies: dict):
    if not cookies:
        return
    with _clearance_lock:
        _clearance_cache[domain] = {"cookies": dict(cookies), "ts": time.time()}


def _invalidate_clearance_cache(domain: str = None):
    with _clearance_lock:
        if domain:
            _clearance_cache.pop(domain, None)
        else:
            _clearance_cache.clear()


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _get_api_key():
    from config import get_captcha_setting
    key = get_captcha_setting("api_key", "")
    if not key:
        key = os.environ.get("CAPTCHA_API_KEY", "").strip()
    return key


def _get_provider():
    from config import get_captcha_setting
    return get_captcha_setting("provider", "capsolver")


def _get_fallback_providers(primary=None):
    if primary is None:
        primary = _get_provider()
    return [primary] + [p for p in PROVIDERS if p != primary]


def _stealth_headers(ua: str = None) -> dict:
    ua = ua or random.choice(_BYPASS_USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


def _transfer_cookies(src, dst):
    try:
        if hasattr(src, 'cookies') and hasattr(dst, 'cookies'):
            dst.cookies.update(dict(src.cookies))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def is_cf_challenge(html: str) -> bool:
    if not html or not isinstance(html, str):
        return False
    html_lower = html.lower()
    score = sum(1 for sig in _CF_CHALLENGE_SIGNALS if sig in html_lower)
    return score >= 2


def _extract_cf_sitekey(html: str):
    for pat in _SITEKEY_PATTERNS["turnstile"]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            key = m.group(1)
            if len(key) >= 20:
                return key
    for pat in [
        r'cData["\s:]+["\']([^"\']{20,})["\']',
        r'name=["\']cf-turnstile-response["\'][^>]*value=["\']([^"\']*)["\']',
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m and m.lastindex:
            return m.group(1)
    sm = re.search(
        r'<script[^>]*challenges\.cloudflare\.com/turnstile[^>]*\?([^"\'>\s]+)',
        html, re.IGNORECASE,
    )
    if sm:
        rm = re.search(r'render=([0-9a-zA-Z_-]{20,})', sm.group(1))
        if rm:
            return rm.group(1)
    return None


def _extract_cf_ray(html: str):
    for pat in [
        r'data-ray=["\']([a-f0-9]+)["\']',
        r'Ray ID:\s*<[^>]*>([a-f0-9]+)<',
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def detect_captcha(html: str, url: str = "") -> dict:
    result = {
        "detected": False, "type": None, "sitekey": None,
        "action": None, "details": [], "is_cf_challenge": False, "cf_ray": None,
    }

    if not html or not isinstance(html, str):
        return result

    html_lower = html.lower()

    for ctype, patterns in _CAPTCHA_DETECT_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                result.update(detected=True, type=ctype)
                result["details"].append(f"Matched: {ctype} ({pat[:40]})")
                break
        if result["detected"]:
            break

    if not result["detected"]:
        cf_score = sum(1 for sig in _CF_CHALLENGE_SIGNALS if sig in html_lower)
        if cf_score >= 2:
            result.update(detected=True, type="turnstile", is_cf_challenge=True)
            result["details"].append(f"CF challenge page (score={cf_score})")

    if result["detected"] and result["type"]:
        base = result["type"].replace("_v2", "").replace("_v3", "")
        if base == "recaptcha":
            for pat in _SITEKEY_PATTERNS["recaptcha"]:
                m = re.search(pat, html)
                if m:
                    result["sitekey"] = m.group(1)
                    break
        elif base == "turnstile":
            result["sitekey"] = _extract_cf_sitekey(html)
            result["cf_ray"] = _extract_cf_ray(html)
            if result["sitekey"]:
                result["details"].append(f"Turnstile sitekey: {result['sitekey'][:25]}...")
            else:
                result["is_cf_challenge"] = True
        elif base in _SITEKEY_PATTERNS:
            for pat in _SITEKEY_PATTERNS[base]:
                m = re.search(pat, html)
                if m:
                    result["sitekey"] = m.group(1)
                    break

        if result["type"] == "recaptcha_v3":
            am = re.search(r'action["\s:]+["\'](\w+)["\']', html)
            result["action"] = am.group(1) if am else "submit"

    if result["detected"]:
        _stats["detected"] += 1
        ct = result["type"] or "unknown"
        _stats["by_type"][ct] = _stats["by_type"].get(ct, 0) + 1
        sk = result["sitekey"]
        logger.info(
            f"CAPTCHA detected: {ct} | sitekey={'%s...' % sk[:20] if sk else 'N/A'} | url={url[:55]}"
        )

    return result


# ---------------------------------------------------------------------------
# Free bypass methods (no API needed)
# ---------------------------------------------------------------------------

def _ok_response(text: str, status: int) -> bool:
    return status == 200 and not is_cf_challenge(text)


def _try_cloudscraper(page_url: str, session=None, browser_profile: str = "chrome") -> tuple:
    """Return (html, ua) or (None, None). Optionally syncs cookies with session."""
    try:
        import cloudscraper
        profiles = [
            {"browser": "chrome", "platform": "windows", "mobile": False},
            {"browser": "chrome", "platform": "linux", "mobile": False},
            {"browser": "firefox", "platform": "windows", "mobile": False},
        ]
        for profile in profiles:
            try:
                cs = cloudscraper.create_scraper(browser=profile)
                if session:
                    _transfer_cookies(session, cs)
                r = cs.get(page_url, timeout=20)
                if _ok_response(r.text, r.status_code):
                    if session:
                        _transfer_cookies(cs, session)
                    ua = cs.headers.get("User-Agent", _BYPASS_USER_AGENTS[0])
                    logger.info(f"cloudscraper bypass OK ({profile['browser']}/{profile['platform']})")
                    return r.text, ua
            except Exception:
                continue
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"cloudscraper failed: {str(e)[:60]}")
    return None, None


def _try_curl_cffi(page_url: str, session=None) -> tuple:
    """Return (html, profile_name) or (None, None)."""
    try:
        from curl_cffi import requests as curl_req
        for profile in _CURL_PROFILES:
            try:
                cookies = {}
                if session and hasattr(session, 'cookies'):
                    cookies = dict(session.cookies)
                r = curl_req.get(
                    page_url, impersonate=profile,
                    cookies=cookies, timeout=20, verify=False,
                    allow_redirects=True,
                )
                if _ok_response(r.text, r.status_code):
                    if session and hasattr(session, 'cookies'):
                        try:
                            session.cookies.update(dict(r.cookies))
                        except Exception:
                            pass
                    logger.info(f"curl_cffi bypass OK (profile={profile})")
                    return r.text, f"curl_cffi/{profile}"
            except Exception:
                continue
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"curl_cffi failed: {str(e)[:60]}")
    return None, None


def _try_flaresolverr(page_url: str, host: str = "http://localhost:8191", timeout: int = 45) -> dict | None:
    """Try local FlareSolverr instance. Returns bypass result dict or None."""
    try:
        payload = {"cmd": "request.get", "url": page_url, "maxTimeout": timeout * 1000}
        r = requests.post(f"{host}/v1", json=payload, timeout=timeout + 10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "ok":
                solution = data.get("solution", {})
                html = solution.get("response", "")
                if html and not is_cf_challenge(html):
                    cookies = {c["name"]: c["value"] for c in solution.get("cookies", [])}
                    logger.info("FlareSolverr bypass OK")
                    return {
                        "solved": True, "needed": True, "captcha_type": "turnstile",
                        "token": "flaresolverr", "provider": "flaresolverr",
                        "cleared_html": html, "cookies": cookies, "user_agent": solution.get("userAgent"),
                    }
    except requests.exceptions.ConnectionError:
        pass  # FlareSolverr not running, silently skip
    except Exception as e:
        logger.debug(f"FlareSolverr failed: {str(e)[:50]}")
    return None


def _try_ua_rotation(page_url: str, session, retries: int = 4) -> tuple:
    """Pure UA + header rotation via existing session. Return (html, ua) or (None, None)."""
    for attempt in range(retries):
        ua = random.choice(_BYPASS_USER_AGENTS)
        try:
            # Clear stale CF cookies
            for cookie in list(getattr(session, 'cookies', [])):
                if any(x in cookie.name.lower() for x in ('cf_', '__cf', 'cf-')):
                    try:
                        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
                    except Exception:
                        pass

            session.headers.update(_stealth_headers(ua))
            time.sleep(0.2 + random.random() * 0.5 * (attempt + 1))
            r = session.get(page_url, timeout=18, verify=False, allow_redirects=True)
            if _ok_response(r.text, r.status_code):
                logger.info(f"UA rotation bypass OK (attempt {attempt+1})")
                return r.text, ua
        except Exception as e:
            logger.debug(f"UA rotation attempt {attempt+1} failed: {str(e)[:40]}")
    return None, None


def _free_cf_bypass(session, page_url: str, max_retries: int = 3) -> tuple:
    """
    Full free bypass chain for CF/Turnstile challenges.
    Returns (cleared_html, user_agent) or (None, None).
    """
    # 1. cloudscraper
    html, ua = _try_cloudscraper(page_url, session)
    if html:
        return html, ua

    # 2. curl_cffi
    html, ua = _try_curl_cffi(page_url, session)
    if html:
        return html, ua

    # 3. FlareSolverr (local)
    result = _try_flaresolverr(page_url)
    if result:
        if session and result.get("cookies"):
            try:
                session.cookies.update(result["cookies"])
            except Exception:
                pass
        return result["cleared_html"], result.get("user_agent", "flaresolverr")

    # 4. UA rotation
    html, ua = _try_ua_rotation(page_url, session, retries=max_retries)
    if html:
        return html, ua

    return None, None


def _submit_cf_clearance(session, page_url: str, token: str, html: str = "") -> tuple:
    """POST token to CF challenge form, return (html, success)."""
    try:
        parsed = urlparse(page_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        form_m = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', html, re.IGNORECASE)
        challenge_url = None
        if form_m:
            ap = form_m.group(1)
            challenge_url = ap if ap.startswith("http") else f"{base}{ap if ap.startswith('/') else '/' + ap}"

        hidden = {}
        for pat in [
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
        ]:
            for m in re.finditer(pat, html, re.IGNORECASE):
                hidden.setdefault(m.group(1), m.group(2))
        hidden["cf-turnstile-response"] = token

        if challenge_url:
            r = session.post(challenge_url, data=hidden, timeout=15, verify=False, allow_redirects=True)
            if r.status_code == 200 and not is_cf_challenge(r.text):
                return r.text, True
            if r.history and not is_cf_challenge(r.text):
                return r.text, True

        time.sleep(0.3)
        r2 = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
        if r2.status_code == 200 and not is_cf_challenge(r2.text):
            return r2.text, True

        cf_cookies = [c for c in getattr(session, 'cookies', []) if 'cf_clearance' in c.name.lower()]
        if cf_cookies:
            r3 = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
            if r3.status_code == 200:
                return r3.text, True

        return None, False
    except Exception as e:
        logger.debug(f"CF clearance submit error: {str(e)[:60]}")
        return None, False


# ---------------------------------------------------------------------------
# Paid API solver (optional — only used when api_key is set)
# ---------------------------------------------------------------------------

def solve_captcha(captcha_type: str, sitekey: str, page_url: str,
                  provider: str = "capsolver", api_key: str = "",
                  timeout: int = 120, max_wait: int = 180,
                  action: str = None, proxy: str = None) -> dict:
    if not api_key:
        api_key = _get_api_key()
    if not provider:
        provider = _get_provider()
    if not api_key:
        return {"success": False, "token": None, "error": "No solver API key"}
    if not sitekey:
        return {"success": False, "token": None, "error": "No sitekey found"}
    if provider not in PROVIDERS:
        return {"success": False, "token": None, "error": f"Unknown provider: {provider}"}

    prov = PROVIDERS[provider]
    task = _build_task(captcha_type, sitekey, page_url, action, proxy, provider)
    if not task:
        return {"success": False, "token": None, "error": f"Unsupported type: {captcha_type}"}

    t0 = time.time()
    try:
        r = requests.post(
            f"{prov['base_url']}{prov['create_task']}",
            json={"clientKey": api_key, "task": task}, timeout=30,
        )
        resp = r.json()
        if resp.get("errorId", 0) != 0:
            err = resp.get("errorDescription", resp.get("errorCode", "Unknown"))
            _stats["failed"] += 1
            return {"success": False, "token": None, "error": err}

        task_id = resp.get("taskId")
        if not task_id:
            token = (resp.get("solution", {}).get("gRecaptchaResponse") or
                     resp.get("solution", {}).get("token") or
                     resp.get("solution", {}).get("text"))
            if token:
                elapsed = time.time() - t0
                _stats["solved"] += 1
                _stats["total_time"] += elapsed
                return {"success": True, "token": token, "time": elapsed,
                        "provider": provider, "user_agent": resp.get("solution", {}).get("userAgent")}
            _stats["failed"] += 1
            return {"success": False, "token": None, "error": "No task ID"}

        logger.info(f"CAPTCHA task created ({provider}): {task_id}")
        poll = 3
        waited = 0
        while waited < max_wait:
            time.sleep(poll)
            waited += poll
            r2 = requests.post(
                f"{prov['base_url']}{prov['get_result']}",
                json={"clientKey": api_key, "taskId": task_id}, timeout=20,
            )
            res = r2.json()
            if res.get("errorId", 0) != 0:
                _stats["failed"] += 1
                return {"success": False, "token": None, "error": res.get("errorDescription", "Poll error")}
            if res.get("status") == "ready":
                sol = res.get("solution", {})
                token = (sol.get("gRecaptchaResponse") or sol.get("token") or
                         sol.get("text") or sol.get("turnstileToken") or sol.get("cf_clearance"))
                if token:
                    elapsed = time.time() - t0
                    _stats["solved"] += 1
                    _stats["total_time"] += elapsed
                    logger.info(f"CAPTCHA solved ({provider}): {elapsed:.1f}s type={captcha_type}")
                    return {"success": True, "token": token, "time": elapsed,
                            "provider": provider, "user_agent": sol.get("userAgent")}
                _stats["failed"] += 1
                return {"success": False, "token": None, "error": "Solution empty"}
            poll = min(poll + 0.5, 5)

        _stats["failed"] += 1
        return {"success": False, "token": None, "error": f"Timeout after {max_wait}s"}

    except requests.exceptions.Timeout:
        _stats["failed"] += 1
        return {"success": False, "token": None, "error": "API timeout"}
    except Exception as e:
        _stats["failed"] += 1
        return {"success": False, "token": None, "error": str(e)[:80]}


def solve_captcha_with_fallback(captcha_type: str, sitekey: str, page_url: str,
                                action: str = None, proxy: str = None,
                                timeout: int = 120, max_wait: int = 180) -> dict:
    """Try each configured API provider in order; return first success."""
    api_key = _get_api_key()
    if not api_key:
        return {"success": False, "token": None, "error": "No solver API key"}
    last_error = "No providers"
    for provider in _get_fallback_providers():
        result = solve_captcha(
            captcha_type, sitekey, page_url, provider=provider, api_key=api_key,
            timeout=timeout, max_wait=max_wait, action=action, proxy=proxy,
        )
        if result["success"]:
            return result
        last_error = result.get("error", "Unknown")
        logger.warning(f"Provider {provider} failed: {last_error}")
    return {"success": False, "token": None, "error": last_error}


def _build_task(captcha_type, sitekey, page_url, action=None, proxy=None,
                provider="capsolver", is_cf_challenge=False):
    proxy_fields = _format_proxy(proxy) if proxy else {}
    proxyless = not proxy

    if captcha_type == "recaptcha_v2":
        task = {"type": "ReCaptchaV2TaskProxyLess" if proxyless else "ReCaptchaV2Task",
                "websiteURL": page_url, "websiteKey": sitekey}
    elif captcha_type == "recaptcha_v3":
        task = {"type": "ReCaptchaV3TaskProxyLess" if proxyless else "ReCaptchaV3Task",
                "websiteURL": page_url, "websiteKey": sitekey,
                "pageAction": action or "submit"}
        if provider == "capsolver":
            task["minScore"] = 0.7
    elif captcha_type == "hcaptcha":
        task = {"type": "HCaptchaTaskProxyLess" if proxyless else "HCaptchaTask",
                "websiteURL": page_url, "websiteKey": sitekey}
    elif captcha_type == "turnstile":
        if provider == "capsolver":
            if is_cf_challenge and not sitekey:
                task = {"type": "AntiCloudflareTask", "websiteURL": page_url}
            else:
                task = {"type": "AntiTurnstileTaskProxyLess" if proxyless else "AntiTurnstileTask",
                        "websiteURL": page_url, "websiteKey": sitekey}
        else:
            task = {"type": "TurnstileTaskProxyless" if proxyless else "TurnstileTask",
                    "websiteURL": page_url, "websiteKey": sitekey}
    else:
        return None

    task.update(proxy_fields)
    return task


def _format_proxy(proxy_str: str) -> dict:
    if not proxy_str:
        return {}
    clean = proxy_str.replace("http://", "").replace("https://", "")
    if "@" in clean:
        auth, host_part = clean.rsplit("@", 1)
        user, passwd = auth.split(":", 1) if ":" in auth else (auth, "")
        host, port = host_part.rsplit(":", 1) if ":" in host_part else (host_part, "8080")
    else:
        parts = clean.split(":")
        if len(parts) == 4:
            host, port, user, passwd = parts
        elif len(parts) == 2:
            host, port, user, passwd = parts[0], parts[1], "", ""
        else:
            return {}
    return {
        "proxyType": "http",
        "proxyAddress": host,
        "proxyPort": int(port) if str(port).isdigit() else 8080,
        "proxyLogin": user,
        "proxyPassword": passwd,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def auto_solve_page(html: str, page_url: str, provider: str = None, api_key: str = None,
                    timeout: int = 120, max_wait: int = 180,
                    proxy: str = None, session=None) -> dict:
    """
    Detect and bypass/solve any CAPTCHA on a page.

    Priority (no API key needed for steps 1-6):
      1. cf_clearance cookie cache (instant if cached)
      2. cloudscraper (CF JS challenge + some hCaptcha)
      3. curl_cffi Chrome/Safari TLS fingerprint impersonation
      4. FlareSolverr local service (localhost:8191)
      5. UA/header rotation (4 attempts)
      6. Skip-token attempt (reCAPTCHA v3 — many WC sites don't validate server-side)
      7. Paid API solver (capsolver → 2captcha → anticaptcha) if api_key is set
    """
    t0 = time.time()
    detection = detect_captcha(html, page_url)

    if not detection["detected"]:
        return {"solved": False, "needed": False, "captcha_type": None,
                "token": None, "details": "No CAPTCHA detected"}

    captcha_type = detection["type"]
    sitekey = detection["sitekey"]
    is_cf = detection.get("is_cf_challenge", False)
    domain = urlparse(page_url).netloc

    def _bypass_result(method, cleared_html=None, ua=None, cookies=None):
        _record_bypass(method, captcha_type)
        if session and cookies:
            try:
                session.cookies.update(cookies)
            except Exception:
                pass
        logger.info(f"CAPTCHA bypassed via {method} ({captcha_type}) in {time.time()-t0:.1f}s")
        return {
            "solved": True, "needed": True, "captcha_type": captcha_type,
            "token": "free_bypass", "provider": method,
            "cleared_html": cleared_html, "user_agent": ua,
            "details": detection["details"], "is_cf_challenge": is_cf, "error": None,
        }

    # ------------------------------------------------------------------
    # Step 1: cf_clearance cookie cache
    # ------------------------------------------------------------------
    if is_cf or captcha_type == "turnstile":
        cached_cookies = _get_clearance_cache(domain)
        if cached_cookies and session:
            try:
                session.cookies.update(cached_cookies)
                r = session.get(page_url, timeout=12, verify=False, allow_redirects=True)
                if _ok_response(r.text, r.status_code):
                    logger.info(f"CF clearance served from cache ({domain})")
                    return _bypass_result("cache", cleared_html=r.text)
                _invalidate_clearance_cache(domain)
            except Exception:
                _invalidate_clearance_cache(domain)

    # ------------------------------------------------------------------
    # Step 2–5: free CF/Turnstile bypass chain
    # ------------------------------------------------------------------
    if is_cf or captcha_type == "turnstile":
        cleared_html, ua = _free_cf_bypass(session, page_url, max_retries=4)
        if cleared_html:
            if session:
                _set_clearance_cache(domain, dict(getattr(session, 'cookies', {})))
            return _bypass_result("free_cf_bypass", cleared_html=cleared_html, ua=ua)

    # ------------------------------------------------------------------
    # Step 2–4 for hCaptcha: cloudscraper → curl_cffi → FlareSolverr
    # ------------------------------------------------------------------
    if captcha_type == "hcaptcha":
        html_cs, ua_cs = _try_cloudscraper(page_url, session)
        if html_cs:
            return _bypass_result("cloudscraper", cleared_html=html_cs, ua=ua_cs)

        html_cc, ua_cc = _try_curl_cffi(page_url, session)
        if html_cc:
            return _bypass_result("curl_cffi", cleared_html=html_cc, ua=ua_cc)

        fs = _try_flaresolverr(page_url)
        if fs:
            return _bypass_result("flaresolverr", cleared_html=fs.get("cleared_html"),
                                  ua=fs.get("user_agent"), cookies=fs.get("cookies"))

    # ------------------------------------------------------------------
    # Step 6: reCAPTCHA skip-token attempt
    # Many WooCommerce/donation sites embed reCAPTCHA but don't validate it.
    # Return a hollow "skip" so the gate module can attempt submission
    # with an empty token; if it 200s, the site doesn't enforce it.
    # ------------------------------------------------------------------
    if captcha_type in ("recaptcha_v2", "recaptcha_v3"):
        logger.info(f"reCAPTCHA detected — attempting skip-token submission (server-side enforcement unknown)")
        _record_bypass("skip_attempt", captcha_type)
        return {
            "solved": True, "needed": True, "captcha_type": captcha_type,
            "token": "", "provider": "skip_attempt",
            "cleared_html": None, "user_agent": None,
            "details": detection["details"] + ["Skip-token: submitting without reCAPTCHA token"],
            "is_cf_challenge": False, "error": None,
        }

    # ------------------------------------------------------------------
    # Step 7: paid API solver (optional — only when api_key is configured)
    # ------------------------------------------------------------------
    if not api_key:
        api_key = _get_api_key()

    if api_key and sitekey:
        result = solve_captcha_with_fallback(
            captcha_type=captcha_type, sitekey=sitekey, page_url=page_url,
            action=detection.get("action"), proxy=proxy,
            timeout=timeout, max_wait=max_wait,
        )
        cleared_html = None
        if result["success"] and session:
            _inject_token(session, captcha_type, result["token"], html)
            if is_cf or captcha_type == "turnstile":
                cleared_html, cf_ok = _submit_cf_clearance(session, page_url, result["token"], html)
                if cf_ok:
                    _set_clearance_cache(domain, dict(getattr(session, 'cookies', {})))
                elif session:
                    try:
                        r = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
                        if _ok_response(r.text, r.status_code):
                            cleared_html = r.text
                    except Exception:
                        pass

        if not result["success"] and session:
            # Last-ditch free bypass after API failure
            cleared_html2, ua2 = _free_cf_bypass(session, page_url)
            if cleared_html2:
                return _bypass_result("free_cf_bypass_fallback", cleared_html=cleared_html2, ua=ua2)

        return {
            "solved": result["success"], "needed": True,
            "captcha_type": captcha_type, "sitekey": sitekey,
            "token": result.get("token"), "time": result.get("time", 0),
            "provider": result.get("provider", "api"), "error": result.get("error"),
            "details": detection["details"], "is_cf_challenge": is_cf,
            "cleared_html": cleared_html, "user_agent": result.get("user_agent"),
        }

    # All paths exhausted
    _stats["failed"] += 1
    logger.warning(f"All CAPTCHA bypass methods failed for {captcha_type} at {page_url[:60]}")
    return {
        "solved": False, "needed": True, "captcha_type": captcha_type,
        "token": None, "error": "All bypass methods failed (install cloudscraper or curl_cffi for better results)",
        "details": detection["details"], "is_cf_challenge": is_cf,
    }


# ---------------------------------------------------------------------------
# Token injection helpers
# ---------------------------------------------------------------------------

def _inject_token(session, captcha_type: str, token: str, html: str = ""):
    field_map = {
        "recaptcha_v2": "g-recaptcha-response",
        "recaptcha_v3": "g-recaptcha-response",
        "hcaptcha": "h-captcha-response",
        "turnstile": "cf-turnstile-response",
    }
    field = field_map.get(captcha_type, "captcha-response")
    session.__dict__["_captcha_token"] = token
    session.__dict__["_captcha_field"] = field
    session.__dict__["_captcha_info"] = {
        "type": captcha_type, "solved": True, "token_len": len(token) if token else 0,
    }
    if token:
        logger.info(f"CAPTCHA token injected ({captcha_type}, {len(token)} chars)")


def get_captcha_form_data(session) -> dict:
    token = session.__dict__.get("_captcha_token")
    field = session.__dict__.get("_captcha_field")
    if token and field:
        return {field: token}
    return {}
