import re
import time
import json
import random
import requests
import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

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

_CF_CHALLENGE_SIGNALS = [
    "just a moment", "checking your browser", "verify you are human",
    "cloudflare", "cf-chl-bypass", "ray id", "ddos protection",
    "please wait", "enable javascript and cookies",
    "challenge-platform", "cf-please-wait",
]

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

_stats = {
    "detected": 0,
    "solved": 0,
    "failed": 0,
    "bypassed": 0,
    "total_time": 0.0,
    "by_type": {},
}


def get_solver_stats():
    return _stats.copy()


def reset_solver_stats():
    global _stats
    _stats = {
        "detected": 0, "solved": 0, "failed": 0, "bypassed": 0,
        "total_time": 0.0, "by_type": {},
    }


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
    """Return all configured providers with primary first."""
    if primary is None:
        primary = _get_provider()
    return [primary] + [p for p in PROVIDERS if p != primary]


def _extract_cf_sitekey(html):
    for pat in _SITEKEY_PATTERNS["turnstile"]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            key = m.group(1)
            if len(key) >= 20:
                return key

    cf_patterns = [
        r'cData["\s:]+["\']([^"\']{20,})["\']',
        r'action=["\']/?cdn-cgi/challenge-platform[^"\']*["\']',
        r'name=["\']cf-turnstile-response["\'][^>]*value=["\']([^"\']*)["\']',
    ]
    for pat in cf_patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m and m.lastindex:
            return m.group(1)

    script_match = re.search(
        r'<script[^>]*challenges\.cloudflare\.com/turnstile[^>]*\?([^"\'>\s]+)',
        html, re.IGNORECASE
    )
    if script_match:
        params = script_match.group(1)
        render_match = re.search(r'render=([0-9a-zA-Z_-]{20,})', params)
        if render_match:
            return render_match.group(1)

    return None


def _extract_cf_ray(html):
    m = re.search(r'data-ray=["\']([a-f0-9]+)["\']', html, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'Ray ID:\s*<[^>]*>([a-f0-9]+)<', html, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def is_cf_challenge(html):
    if not html or not isinstance(html, str):
        return False
    html_lower = html.lower()
    score = sum(1 for sig in _CF_CHALLENGE_SIGNALS if sig in html_lower)
    return score >= 2


def detect_captcha(html, url=""):
    result = {
        "detected": False,
        "type": None,
        "sitekey": None,
        "action": None,
        "details": [],
        "is_cf_challenge": False,
        "cf_ray": None,
    }

    if not html or not isinstance(html, str):
        return result

    html_lower = html.lower()

    for ctype, patterns in _CAPTCHA_DETECT_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                result["detected"] = True
                result["type"] = ctype
                result["details"].append(f"Matched: {ctype} ({pat[:40]})")
                break
        if result["detected"]:
            break

    if not result["detected"]:
        cf_score = sum(1 for sig in _CF_CHALLENGE_SIGNALS if sig in html_lower)
        if cf_score >= 2:
            result["detected"] = True
            result["type"] = "turnstile"
            result["is_cf_challenge"] = True
            result["details"].append(f"Cloudflare challenge page detected (score={cf_score})")

    if result["detected"] and result["type"]:
        base_type = result["type"].replace("_v2", "").replace("_v3", "")
        if base_type == "recaptcha":
            for pat in _SITEKEY_PATTERNS["recaptcha"]:
                m = re.search(pat, html)
                if m:
                    result["sitekey"] = m.group(1)
                    break
        elif base_type == "turnstile":
            result["sitekey"] = _extract_cf_sitekey(html)
            result["cf_ray"] = _extract_cf_ray(html)
            if result["sitekey"]:
                result["details"].append(f"Turnstile sitekey: {result['sitekey'][:25]}...")
            else:
                result["details"].append("Turnstile: sitekey not found in HTML")
        elif base_type in _SITEKEY_PATTERNS:
            for pat in _SITEKEY_PATTERNS[base_type]:
                m = re.search(pat, html)
                if m:
                    result["sitekey"] = m.group(1)
                    break

        if result["type"] == "recaptcha_v3":
            action_match = re.search(r'action["\s:]+["\'](\w+)["\']', html)
            if action_match:
                result["action"] = action_match.group(1)
            else:
                result["action"] = "submit"

    if result["detected"]:
        _stats["detected"] += 1
        ctype = result["type"] or "unknown"
        _stats["by_type"][ctype] = _stats["by_type"].get(ctype, 0) + 1
        logger.info(f"CAPTCHA detected: {ctype}, sitekey={result['sitekey'][:25] + '...' if result['sitekey'] else 'N/A'}, url={url[:60]}")

    return result


def solve_captcha(captcha_type, sitekey, page_url, provider="capsolver", api_key="",
                  timeout=120, max_wait=180, action=None, proxy=None):
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

    prov_config = PROVIDERS[provider]
    base_url = prov_config["base_url"]

    task = _build_task(captcha_type, sitekey, page_url, action, proxy, provider)
    if not task:
        return {"success": False, "token": None, "error": f"Cannot build task for {captcha_type}"}

    start_time = time.time()

    try:
        create_payload = {"clientKey": api_key, "task": task}
        logger.info(f"CAPTCHA solving: {captcha_type} via {provider}, sitekey={sitekey[:20]}...")
        r = requests.post(f"{base_url}{prov_config['create_task']}",
                          json=create_payload, timeout=30)
        resp = r.json()

        if resp.get("errorId", 0) != 0:
            error_msg = resp.get("errorDescription", resp.get("errorCode", "Unknown error"))
            logger.error(f"CAPTCHA create task failed ({provider}): {error_msg}")
            _stats["failed"] += 1
            return {"success": False, "token": None, "error": error_msg}

        task_id = resp.get("taskId")
        if not task_id:
            token = resp.get("solution", {}).get("gRecaptchaResponse") or \
                    resp.get("solution", {}).get("token") or \
                    resp.get("solution", {}).get("text")
            if token:
                elapsed = time.time() - start_time
                _stats["solved"] += 1
                _stats["total_time"] += elapsed
                logger.info(f"CAPTCHA solved instantly ({provider}): {elapsed:.1f}s")
                ua = resp.get("solution", {}).get("userAgent")
                return {"success": True, "token": token, "time": elapsed, "provider": provider, "user_agent": ua}
            _stats["failed"] += 1
            return {"success": False, "token": None, "error": "No task ID returned"}

        logger.info(f"CAPTCHA task created ({provider}): {task_id}")

        poll_interval = 3
        waited = 0
        while waited < max_wait:
            time.sleep(poll_interval)
            waited += poll_interval

            result_payload = {"clientKey": api_key, "taskId": task_id}
            r2 = requests.post(f"{base_url}{prov_config['get_result']}",
                               json=result_payload, timeout=20)
            result = r2.json()

            if result.get("errorId", 0) != 0:
                error_msg = result.get("errorDescription", "Unknown error")
                logger.error(f"CAPTCHA poll error ({provider}): {error_msg}")
                _stats["failed"] += 1
                return {"success": False, "token": None, "error": error_msg}

            status = result.get("status", "")
            if status == "ready":
                solution = result.get("solution", {})
                token = (solution.get("gRecaptchaResponse") or
                         solution.get("token") or
                         solution.get("text") or
                         solution.get("turnstileToken") or
                         solution.get("cf_clearance"))
                if token:
                    elapsed = time.time() - start_time
                    _stats["solved"] += 1
                    _stats["total_time"] += elapsed
                    logger.info(f"CAPTCHA solved ({provider}): {elapsed:.1f}s, type={captcha_type}")

                    ua = solution.get("userAgent")
                    return {
                        "success": True, "token": token, "time": elapsed,
                        "provider": provider, "user_agent": ua,
                    }
                else:
                    _stats["failed"] += 1
                    return {"success": False, "token": None, "error": "Solution empty"}

            if poll_interval < 5:
                poll_interval += 0.5

        elapsed = time.time() - start_time
        _stats["failed"] += 1
        logger.warning(f"CAPTCHA solve timeout ({provider}): {elapsed:.1f}s")
        return {"success": False, "token": None, "error": f"Timeout after {max_wait}s"}

    except requests.exceptions.Timeout:
        _stats["failed"] += 1
        return {"success": False, "token": None, "error": "API request timeout"}
    except Exception as e:
        _stats["failed"] += 1
        logger.error(f"CAPTCHA solver error: {str(e)[:80]}")
        return {"success": False, "token": None, "error": str(e)[:80]}


def solve_captcha_with_fallback(captcha_type, sitekey, page_url, action=None, proxy=None,
                                timeout=120, max_wait=180):
    """Try all configured providers in order, return first success."""
    api_key = _get_api_key()
    if not api_key:
        return {"success": False, "token": None, "error": "No solver API key"}

    providers = _get_fallback_providers()
    last_error = "No providers configured"

    for provider in providers:
        result = solve_captcha(
            captcha_type=captcha_type, sitekey=sitekey, page_url=page_url,
            provider=provider, api_key=api_key, timeout=timeout, max_wait=max_wait,
            action=action, proxy=proxy,
        )
        if result["success"]:
            return result
        last_error = result.get("error", "Unknown error")
        logger.warning(f"Provider {provider} failed ({last_error}), trying next...")

    return {"success": False, "token": None, "error": last_error}


def _build_task(captcha_type, sitekey, page_url, action=None, proxy=None, provider="capsolver",
                is_cf_challenge=False):
    if captcha_type == "recaptcha_v2":
        task = {
            "type": "ReCaptchaV2TaskProxyLess" if not proxy else "ReCaptchaV2Task",
            "websiteURL": page_url,
            "websiteKey": sitekey,
        }
        if proxy:
            task.update(_format_proxy(proxy))
        return task

    elif captcha_type == "recaptcha_v3":
        task = {
            "type": "ReCaptchaV3TaskProxyLess" if not proxy else "ReCaptchaV3Task",
            "websiteURL": page_url,
            "websiteKey": sitekey,
            "pageAction": action or "submit",
        }
        if provider == "capsolver":
            task["minScore"] = 0.7
        if proxy:
            task.update(_format_proxy(proxy))
        return task

    elif captcha_type == "hcaptcha":
        task = {
            "type": "HCaptchaTaskProxyLess" if not proxy else "HCaptchaTask",
            "websiteURL": page_url,
            "websiteKey": sitekey,
        }
        if proxy:
            task.update(_format_proxy(proxy))
        return task

    elif captcha_type == "turnstile":
        if provider == "capsolver":
            if is_cf_challenge and not sitekey:
                # Cloudflare JS/PoW challenge — use AntiCloudflareTask (no sitekey needed)
                task = {
                    "type": "AntiCloudflareTask",
                    "websiteURL": page_url,
                    "proxy": _format_proxy(proxy).get("proxyAddress", "") if proxy else "",
                }
                if proxy:
                    task.update(_format_proxy(proxy))
                return task
            task = {
                "type": "AntiTurnstileTaskProxyLess" if not proxy else "AntiTurnstileTask",
                "websiteURL": page_url,
                "websiteKey": sitekey,
            }
        else:
            task = {
                "type": "TurnstileTaskProxyless" if not proxy else "TurnstileTask",
                "websiteURL": page_url,
                "websiteKey": sitekey,
            }
        if proxy:
            task.update(_format_proxy(proxy))
        return task

    return None


def _format_proxy(proxy_str):
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
            host, port = parts
            user, passwd = "", ""
        else:
            return {}
    return {
        "proxyType": "http",
        "proxyAddress": host,
        "proxyPort": int(port) if port.isdigit() else 8080,
        "proxyLogin": user,
        "proxyPassword": passwd,
    }


def _submit_cf_clearance(session, page_url, token, html=""):
    try:
        parsed = urlparse(page_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        form_match = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', html, re.IGNORECASE
        )
        challenge_url = None
        if form_match:
            action_path = form_match.group(1)
            if action_path.startswith("http"):
                challenge_url = action_path
            elif action_path.startswith("/"):
                challenge_url = f"{base}{action_path}"
            else:
                challenge_url = f"{base}/{action_path}"

        hidden_fields = {}
        for m in re.finditer(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            html, re.IGNORECASE
        ):
            hidden_fields[m.group(1)] = m.group(2)
        for m in re.finditer(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
            html, re.IGNORECASE
        ):
            if m.group(1) not in hidden_fields:
                hidden_fields[m.group(1)] = m.group(2)

        hidden_fields["cf-turnstile-response"] = token

        if challenge_url:
            logger.info(f"CF challenge submit to: {challenge_url[:60]}, fields={len(hidden_fields)}")
            r = session.post(
                challenge_url, data=hidden_fields,
                timeout=15, verify=False, allow_redirects=True
            )
            if r.status_code == 200 and "just a moment" not in r.text.lower():
                logger.info(f"CF challenge submitted OK: {r.status_code}, len={len(r.text)}")
                return r.text, True
            elif r.history and len(r.history) > 0:
                logger.info(f"CF challenge redirected: final={r.status_code}")
                if "just a moment" not in r.text.lower():
                    return r.text, True

        time.sleep(0.3)
        r2 = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
        if r2.status_code == 200 and "just a moment" not in r2.text.lower():
            logger.info(f"CF clearance obtained via page reload: {r2.status_code}")
            return r2.text, True

        cf_cookies = [c for c in session.cookies if 'cf_clearance' in c.name.lower()]
        if cf_cookies:
            logger.info(f"CF clearance cookie found: {cf_cookies[0].name}")
            r3 = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
            if r3.status_code == 200:
                return r3.text, True

        logger.warning(f"CF clearance failed: status={r2.status_code}")
        return None, False

    except Exception as e:
        logger.error(f"CF clearance submission error: {str(e)[:60]}")
        return None, False


def _free_cf_bypass(session, page_url, max_retries=3):
    # 1. Try cloudscraper — handles CF JS challenge automatically
    try:
        import cloudscraper
        cs = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )
        if hasattr(session, 'cookies'):
            try:
                cs.cookies.update(dict(session.cookies))
            except Exception:
                pass
        r = cs.get(page_url, timeout=20)
        if r.status_code == 200 and not is_cf_challenge(r.text):
            if hasattr(session, 'cookies'):
                try:
                    session.cookies.update(dict(cs.cookies))
                except Exception:
                    pass
            _stats["bypassed"] += 1
            logger.info("CF bypass via cloudscraper OK")
            return r.text, cs.headers.get("User-Agent", _BYPASS_USER_AGENTS[0])
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"cloudscraper CF bypass failed: {str(e)[:60]}")

    # 2. Try curl_cffi — Chrome TLS fingerprint bypasses bot detection
    try:
        from curl_cffi import requests as curl_req
        curl_resp = curl_req.get(page_url, impersonate="chrome110", timeout=20, verify=False)
        if curl_resp.status_code == 200 and not is_cf_challenge(curl_resp.text):
            _stats["bypassed"] += 1
            logger.info("CF bypass via curl_cffi OK")
            return curl_resp.text, "curl_cffi/chrome110"
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"curl_cffi CF bypass failed: {str(e)[:60]}")

    # 3. UA rotation fallback with proper browser headers
    for attempt in range(max_retries):
        ua = random.choice(_BYPASS_USER_AGENTS)
        session.headers['user-agent'] = ua

        try:
            if hasattr(session, 'cookies'):
                for cookie in list(session.cookies):
                    if 'cf' in cookie.name.lower() or '__cf' in cookie.name.lower():
                        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        except Exception:
            pass

        try:
            session.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            })

            time.sleep(0.2 + random.random() * 0.3)

            r = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
            if r.status_code == 200 and not is_cf_challenge(r.text):
                logger.info(f"CF bypass success on attempt {attempt+1} with UA rotation")
                _stats["bypassed"] += 1
                return r.text, ua
        except Exception as e:
            logger.debug(f"CF bypass attempt {attempt+1} failed: {str(e)[:40]}")
            continue

        time.sleep(0.5 * (attempt + 1))

    return None, None


def _free_captcha_bypass(session, page_url, captcha_type, html):
    if captcha_type == "turnstile" or is_cf_challenge(html):
        cleared, ua = _free_cf_bypass(session, page_url, max_retries=4)
        if cleared:
            return {
                "solved": True, "needed": True, "captcha_type": captcha_type,
                "token": "bypass", "time": 0, "provider": "free_bypass",
                "details": ["Cloudflare bypassed via session rotation"],
                "is_cf_challenge": True, "cleared_html": cleared,
                "user_agent": ua, "error": None, "sitekey": None,
            }

    return None


def auto_solve_page(html, page_url, provider=None, api_key=None,
                    timeout=120, max_wait=180, proxy=None, session=None):
    detection = detect_captcha(html, page_url)

    if not detection["detected"]:
        return {
            "solved": False,
            "needed": False,
            "captcha_type": None,
            "token": None,
            "details": "No CAPTCHA detected",
        }

    captcha_type = detection["type"]
    sitekey = detection["sitekey"]
    is_cf = detection.get("is_cf_challenge", False)

    if not api_key:
        api_key = _get_api_key()
    if not provider:
        provider = _get_provider()

    if session and (is_cf or captcha_type == "turnstile"):
        if not api_key or not sitekey:
            bypass_result = _free_captcha_bypass(session, page_url, captcha_type, html)
            if bypass_result:
                return bypass_result

    if not sitekey:
        if session and is_cf:
            bypass_result = _free_captcha_bypass(session, page_url, captcha_type, html)
            if bypass_result:
                return bypass_result

        detail_msg = f"{CAPTCHA_TYPES.get(captcha_type, captcha_type)} detected but sitekey not found"
        if is_cf:
            detail_msg = "Cloudflare challenge detected - attempting bypass"
        return {
            "solved": False,
            "needed": True,
            "captcha_type": captcha_type,
            "token": None,
            "details": detail_msg,
            "is_cf_challenge": is_cf,
        }

    if not api_key:
        if session:
            bypass_result = _free_captcha_bypass(session, page_url, captcha_type, html)
            if bypass_result:
                return bypass_result

        _stats["bypassed"] += 1
        return {
            "solved": False,
            "needed": True,
            "captcha_type": captcha_type,
            "token": None,
            "details": f"No API key - free bypass failed",
            "is_cf_challenge": is_cf,
        }

    # Use fallback-aware solver: tries primary provider then falls back to others
    result = solve_captcha_with_fallback(
        captcha_type=captcha_type,
        sitekey=sitekey,
        page_url=page_url,
        action=detection.get("action"),
        proxy=proxy,
        timeout=timeout,
        max_wait=max_wait,
    )

    cleared_html = None
    if result["success"] and session:
        _inject_token(session, captcha_type, result["token"], html)

        if is_cf or captcha_type == "turnstile":
            cleared_html, cf_ok = _submit_cf_clearance(session, page_url, result["token"], html)
            if not cf_ok:
                logger.warning("CAPTCHA solved but CF clearance submission failed, retrying page...")
                try:
                    r = session.get(page_url, timeout=15, verify=False, allow_redirects=True)
                    if r.status_code == 200 and not is_cf_challenge(r.text):
                        cleared_html = r.text
                        logger.info("CF clearance obtained on retry")
                except Exception:
                    pass

    if not result["success"] and session:
        bypass_result = _free_captcha_bypass(session, page_url, captcha_type, html)
        if bypass_result:
            return bypass_result

    return {
        "solved": result["success"],
        "needed": True,
        "captcha_type": captcha_type,
        "sitekey": sitekey,
        "token": result.get("token"),
        "time": result.get("time", 0),
        "provider": result.get("provider", provider),
        "error": result.get("error"),
        "details": detection["details"],
        "is_cf_challenge": is_cf,
        "cleared_html": cleared_html,
        "user_agent": result.get("user_agent"),
    }


def _inject_token(session, captcha_type, token, html=""):
    if captcha_type in ("recaptcha_v2", "recaptcha_v3"):
        session.__dict__['_captcha_token'] = token
        session.__dict__['_captcha_field'] = 'g-recaptcha-response'
    elif captcha_type == "hcaptcha":
        session.__dict__['_captcha_token'] = token
        session.__dict__['_captcha_field'] = 'h-captcha-response'
    elif captcha_type == "turnstile":
        session.__dict__['_captcha_token'] = token
        session.__dict__['_captcha_field'] = 'cf-turnstile-response'

    session.__dict__['_captcha_info'] = {
        "type": captcha_type,
        "solved": True,
        "token_len": len(token) if token else 0,
    }
    logger.info(f"CAPTCHA token injected into session ({captcha_type}, {len(token)} chars)")


def get_captcha_form_data(session):
    token = session.__dict__.get('_captcha_token')
    field = session.__dict__.get('_captcha_field')
    if token and field:
        return {field: token}
    return {}
