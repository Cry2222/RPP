import subprocess
import shutil
import json
import re
import tempfile
import os
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_STRIPE_KEY_RE = re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{20,}')
_STRIPE_ACCT_RE = re.compile(r'acct_[A-Za-z0-9]{16,}')
_BT_MERCHANT_RE = re.compile(r'merchants/([a-z0-9]{16})/client_api')
_BT_TOKEN_RE = re.compile(
    r'(?:client_token|clientToken|braintree_client_token|braintreeClientToken)'
    r'\s*[=:]\s*["\']([A-Za-z0-9+/=]{50,})["\']'
)
_WC_SIGNALS = [
    "woocommerce-register-nonce", "woocommerce-login-nonce",
    "add_card_nonce", "woocommerce-add-payment-method-nonce",
    "wc_stripe_create_setup_intent", "wc_stripe_frontend_request",
    "wc_braintree_client_token", "wc-ajax",
    "_charitable_donation_nonce", "charitable_form_id",
    "setup-intent", "setup_intent",
]
_DONATE_KEYWORDS = ("/donate", "/give", "/support", "/contribut", "/donation")
_ACCOUNT_KEYWORDS = ("/my-account", "/account/")
_PAYMENT_PATHS = [
    "/donate/", "/donations/", "/give/", "/support/", "/contribute/",
    "/my-account/", "/my-account-2/", "/account/",
    "/my-account/add-payment-method/", "/my-account-2/add-payment-method/",
    "/checkout/", "/checkout/onepage", "/cart/", "/shop/",
    "/orders/populate", "/cart/add",
]


def is_available():
    """Returns True if the js-recon CLI is installed and on PATH."""
    return shutil.which("js-recon") is not None


def jsrecon_scan(url, timeout=120):
    """
    Runs ``js-recon run`` against *url*, downloading and analysing all
    dynamically loaded JS bundles.  Extracts Stripe keys, Braintree merchant
    IDs, client tokens, WooCommerce nonces, and API paths that are invisible
    to plain HTML scraping.

    Returns a findings dict on success, or None if js-recon is not installed
    or produces no usable output.  Never raises — failures are logged silently
    so callers can treat the result as an optional enhancement.
    """
    if not is_available():
        return None

    url = url.strip()
    if not url.startswith("http"):
        url = f"https://{url}"

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            subprocess.run(
                ["js-recon", "run", "-u", url,
                 "--output", tmpdir, "--secrets", "--yes"],
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired:
            logger.warning("js-recon timed out scanning %s", url)
            return None
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.debug("js-recon scan error: %s", exc)
            return None

        host = urlparse(url).netloc.replace(":", "_")
        findings = _parse_output(tmpdir, host)

    return findings if _has_findings(findings) else None


# ── internal helpers ─────────────────────────────────────────────────────────

def _has_findings(f):
    return any([
        f["stripe_keys"], f["stripe_accounts"], f["merchant_ids"],
        f["bt_client_tokens"], f["endpoints"], f["wc_signals"],
    ])


def _parse_output(root, host):
    findings = {
        "stripe_keys": [],
        "stripe_accounts": [],
        "merchant_ids": [],
        "bt_client_tokens": [],
        "endpoints": [],
        "wc_signals": [],
        "donate_paths": [],
        "account_paths": [],
    }

    text_parts = []

    for search_dir in [os.path.join(root, host), root]:
        if not os.path.isdir(search_dir):
            continue
        for fname in os.listdir(search_dir):
            fpath = os.path.join(search_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                raw = open(fpath, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue

            if fname.endswith(".json"):
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        # strings.json format: {filepath: [strings]}
                        for val in data.values():
                            if isinstance(val, list):
                                text_parts.extend(str(s) for s in val)
                            elif isinstance(val, str):
                                text_parts.append(val)
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                text_parts.append(item)
                                if item.startswith("/"):
                                    findings["endpoints"].append(item)
                            elif isinstance(item, dict):
                                for key in ("path", "url", "endpoint"):
                                    if key in item and isinstance(item[key], str):
                                        text_parts.append(item[key])
                                        if item[key].startswith("/"):
                                            findings["endpoints"].append(item[key])
                                        break
                except json.JSONDecodeError:
                    text_parts.append(raw)
            else:
                text_parts.append(raw)

    all_text = "\n".join(text_parts)
    if not all_text.strip():
        return findings

    findings["stripe_keys"] = list(dict.fromkeys(_STRIPE_KEY_RE.findall(all_text)))
    findings["stripe_accounts"] = list(dict.fromkeys(_STRIPE_ACCT_RE.findall(all_text)))
    findings["merchant_ids"] = list(dict.fromkeys(_BT_MERCHANT_RE.findall(all_text)))

    for m in _BT_TOKEN_RE.finditer(all_text):
        tok = m.group(1)
        if tok not in findings["bt_client_tokens"]:
            findings["bt_client_tokens"].append(tok)

    text_lower = all_text.lower()
    findings["wc_signals"] = [s for s in _WC_SIGNALS if s in text_lower]

    for path in _PAYMENT_PATHS:
        if path in all_text:
            findings["endpoints"].append(path)
            if any(k in path for k in _DONATE_KEYWORDS):
                findings["donate_paths"].append(path)
            if any(k in path for k in _ACCOUNT_KEYWORDS):
                findings["account_paths"].append(path)

    findings["endpoints"] = list(dict.fromkeys(findings["endpoints"]))
    findings["donate_paths"] = list(dict.fromkeys(findings["donate_paths"]))
    findings["account_paths"] = list(dict.fromkeys(findings["account_paths"]))

    return findings
