import requests
import re
import sys
import urllib3
import warnings
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

SITES = [
    ("simplygreatdeals.co.uk", "/my-account-2/"),
    ("on8mil.com", "/my-account-2/"),
    ("rainbows-uniform.co.uk", None),
    ("gofrolic.co.uk", None),
    ("kebabskee.co.uk", None),
    ("nutratea.co.uk", None),
    ("ladies-paradise.co.uk", None),
    ("supporterstravel.co.uk", None),
    ("totemtimber.co.uk", None),
    ("palmersquare.com", None),
    ("aceclassics.co.uk", None),
    ("millfieldshop.com", None),
    ("elixirgardensupplies.co.uk", None),
    ("revivify.com", None),
    ("thetfordgardencentre.co.uk", None),
]

ACCOUNT_PATHS = ["/my-account-2/", "/my-account/", "/account/"]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

def probe_site(domain, hint_path=None):
    url = f"https://{domain}"
    result = {
        "domain": domain,
        "reachable": False,
        "stripe": False,
        "braintree": False,
        "woocommerce": False,
        "account_path": None,
        "stripe_key": None,
        "merchant_id": None,
        "add_pm": False,
        "setup_intent": False,
        "cloudflare": False,
        "errors": [],
    }

    s = requests.Session()
    s.headers.update({"User-Agent": UA})

    try:
        r = s.get(url, verify=False, timeout=12, allow_redirects=True)
        if r.status_code == 403 and ("just a moment" in r.text.lower() or "cloudflare" in r.text.lower()):
            result["cloudflare"] = True
            result["errors"].append("Cloudflare protected")
        if r.status_code == 200:
            result["reachable"] = True
        else:
            result["errors"].append(f"HTTP {r.status_code}")
            if not result["cloudflare"]:
                return result
    except Exception as e:
        result["errors"].append(f"Connection: {str(e)[:60]}")
        return result

    all_html = r.text

    paths_to_try = [hint_path] if hint_path else ACCOUNT_PATHS
    if hint_path:
        paths_to_try = [hint_path] + [p for p in ACCOUNT_PATHS if p != hint_path]

    for pg in paths_to_try:
        try:
            pr = s.get(f"{url}{pg}", verify=False, timeout=10, allow_redirects=True)
            if pr.status_code == 200:
                all_html += "\n" + pr.text
                if "woocommerce" in pr.text.lower() or "wc-ajax" in pr.text.lower():
                    result["account_path"] = pg
                    result["woocommerce"] = True
        except Exception:
            continue

    for pm_path_base in (result["account_path"],) if result["account_path"] else ACCOUNT_PATHS:
        pm_url = f"{url}{pm_path_base}add-payment-method/"
        try:
            pr = s.get(pm_url, verify=False, timeout=10, allow_redirects=True)
            if pr.status_code == 200 and ("add_card_nonce" in pr.text or "payment-method" in pr.text.lower()):
                result["add_pm"] = True
                all_html += "\n" + pr.text
                if not result["account_path"]:
                    result["account_path"] = pm_path_base
        except Exception:
            continue

    for extra in ["/checkout/", "/shop/"]:
        try:
            pr = s.get(f"{url}{extra}", verify=False, timeout=8, allow_redirects=True)
            if pr.status_code == 200:
                all_html += "\n" + pr.text
        except Exception:
            continue

    html_lower = all_html.lower()

    if "woocommerce" in html_lower or "wc-ajax" in html_lower:
        result["woocommerce"] = True

    pk_match = re.search(r'(pk_(?:live|test)_[A-Za-z0-9]{20,})', all_html)
    if pk_match:
        result["stripe"] = True
        result["stripe_key"] = pk_match.group(1)

    if "braintree" in html_lower or "wc_braintree" in html_lower:
        result["braintree"] = True
    merchant_match = re.search(r'merchants/([a-z0-9]{16})/client_api', all_html)
    if merchant_match:
        result["braintree"] = True
        result["merchant_id"] = merchant_match.group(1)

    if "wc_stripe_create_setup_intent" in html_lower or "setup-intent" in html_lower or "wc_stripe_frontend_request" in html_lower:
        result["setup_intent"] = True

    try:
        intent_r = s.post(
            f"{url}/?wc-ajax=wc_stripe_frontend_request&path=/wc-stripe/v1/setup-intent",
            data={"payment_method": "stripe_cc"},
            verify=False, timeout=8
        )
        if "client_secret" in intent_r.text or intent_r.status_code in (200, 400):
            result["setup_intent"] = True
    except Exception:
        pass

    return result


def main():
    print("=" * 80)
    print("SITE PROBE - Auto-detecting gate support for all sites")
    print("=" * 80)

    stripe_auth_sites = []
    stripe_intent_sites = []
    braintree_auth_sites = []
    failed_sites = []

    for domain, hint in SITES:
        print(f"\n--- Probing {domain} ---")
        r = probe_site(domain, hint)

        gates = []
        if r["stripe"] and r["woocommerce"]:
            if r["add_pm"]:
                gates.append("Stripe Auth")
                stripe_auth_sites.append((domain, r["account_path"], r["stripe_key"]))
            if r["setup_intent"]:
                gates.append("Stripe Intent")
                stripe_intent_sites.append((domain, r["account_path"], r["stripe_key"]))
            elif r["stripe"]:
                gates.append("Stripe Intent (possible)")
                stripe_intent_sites.append((domain, r["account_path"], r["stripe_key"]))

        if r["braintree"] and r["woocommerce"]:
            gates.append("Braintree Auth")
            braintree_auth_sites.append((domain, r["account_path"], r["merchant_id"]))

        status = "OK" if r["reachable"] else ("CF" if r["cloudflare"] else "FAIL")
        path_str = r["account_path"] or "?"
        key_str = r["stripe_key"][:30] + "..." if r["stripe_key"] else "None"
        gate_str = ", ".join(gates) if gates else "None detected"

        print(f"  Status: {status} | WC: {r['woocommerce']} | Path: {path_str}")
        print(f"  Stripe: {r['stripe']} | Key: {key_str}")
        print(f"  Braintree: {r['braintree']} | Merchant: {r['merchant_id'] or 'None'}")
        print(f"  Setup Intent: {r['setup_intent']} | Add PM: {r['add_pm']}")
        print(f"  CF: {r['cloudflare']}")
        print(f"  GATES: {gate_str}")
        if r["errors"]:
            print(f"  Errors: {'; '.join(r['errors'])}")

        if not gates:
            failed_sites.append(domain)

        time.sleep(0.3)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nStripe Auth compatible ({len(stripe_auth_sites)}):")
    for d, p, k in stripe_auth_sites:
        print(f"  {d} | path={p} | key={k[:25] if k else 'None'}...")
    print(f"\nStripe Intent compatible ({len(stripe_intent_sites)}):")
    for d, p, k in stripe_intent_sites:
        print(f"  {d} | path={p} | key={k[:25] if k else 'None'}...")
    print(f"\nBraintree Auth compatible ({len(braintree_auth_sites)}):")
    for d, p, m in braintree_auth_sites:
        print(f"  {d} | path={p} | merchant={m}")
    print(f"\nFailed/No gate ({len(failed_sites)}):")
    for d in failed_sites:
        print(f"  {d}")


if __name__ == "__main__":
    main()
