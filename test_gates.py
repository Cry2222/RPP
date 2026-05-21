import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import urllib3
import warnings
urllib3.disable_warnings()
warnings.filterwarnings('ignore')

import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_test_cards(path, limit=3):
    cards = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or '|' not in line:
                continue
            parts = line.split('|')
            if len(parts) >= 4:
                cards.append(parts)
            if len(cards) >= limit:
                break
    return cards

def test_stripe_charitable(cards):
    print("\n" + "="*60)
    print("TEST: Stripe Charitable Gate (Config #1)")
    print("="*60)
    try:
        from stripe import check_stripe
        for parts in cards[:2]:
            cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
            print(f"\n  Card: {cc[:6]}***{cc[-4:]}|{mm}|{yy}|{cvv}")
            result = check_stripe(cc, mm, yy, cvv)
            status = result.get('status', '?')
            msg = result.get('response', result.get('message', '?'))
            print(f"  Result: {status} | {msg}")
            time.sleep(1)
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback; traceback.print_exc()

def test_stripe_auth(cards):
    print("\n" + "="*60)
    print("TEST: Stripe Auth Gate (Config #3)")
    print("="*60)
    try:
        from stripe_auth import check_stripe_auth
        from config import GATE_SETTINGS
        settings = GATE_SETTINGS.get("stripe_auth", {})
        print(f"  Site: {settings.get('site_url', '?')}")
        print(f"  Path: {settings.get('account_path', '?')}")
        print(f"  Key: {(settings.get('stripe_pub_key') or 'auto')[:30]}...")
        for parts in cards[:2]:
            cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
            print(f"\n  Card: {cc[:6]}***{cc[-4:]}|{mm}|{yy}|{cvv}")
            result = check_stripe_auth(cc, mm, yy, cvv)
            status = result.get('status', '?')
            msg = result.get('response', result.get('message', '?'))
            retry = result.get('_retry', False)
            print(f"  Result: {status} | {msg} | retry={retry}")
            time.sleep(1)
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback; traceback.print_exc()

def test_stripe_intent(cards):
    print("\n" + "="*60)
    print("TEST: Stripe Intent Gate (Config #4)")
    print("="*60)
    try:
        from stripe_intent import check_stripe_intent
        from config import GATE_SETTINGS
        settings = GATE_SETTINGS.get("stripe_intent", {})
        print(f"  Site: {settings.get('site_url', '?')}")
        print(f"  Path: {settings.get('account_path', '?')}")
        print(f"  Key: {(settings.get('stripe_pub_key') or 'auto')[:30]}...")
        for parts in cards[:2]:
            cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
            print(f"\n  Card: {cc[:6]}***{cc[-4:]}|{mm}|{yy}|{cvv}")
            result = check_stripe_intent(cc, mm, yy, cvv)
            status = result.get('status', '?')
            msg = result.get('response', result.get('message', '?'))
            retry = result.get('_retry', False)
            print(f"  Result: {status} | {msg} | retry={retry}")
            time.sleep(1)
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback; traceback.print_exc()

def test_braintree_auth(cards):
    print("\n" + "="*60)
    print("TEST: Braintree Auth Gate (Config #5)")
    print("="*60)
    try:
        from braintree_auth import check_braintree_auth
        from config import GATE_SETTINGS
        settings = GATE_SETTINGS.get("braintree_auth", {})
        print(f"  Site: {settings.get('site_url', '?')}")
        print(f"  Path: {settings.get('account_path', '?')}")
        print(f"  Merchant: {settings.get('merchant_id', '?')}")
        for parts in cards[:2]:
            cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
            print(f"\n  Card: {cc[:6]}***{cc[-4:]}|{mm}|{yy}|{cvv}")
            result = check_braintree_auth(cc, mm, yy, cvv)
            status = result.get('status', '?')
            msg = result.get('response', result.get('message', '?'))
            retry = result.get('_retry', False)
            print(f"  Result: {status} | {msg} | retry={retry}")
            time.sleep(1)
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback; traceback.print_exc()

def main():
    cards_path = os.path.join(os.path.dirname(__file__), "approved.txt")
    cards = load_test_cards(cards_path, limit=4)
    print(f"Loaded {len(cards)} test cards from approved.txt")

    test_stripe_charitable(cards)
    test_stripe_auth(cards)
    test_stripe_intent(cards)
    test_braintree_auth(cards)

    print("\n" + "="*60)
    print("ALL GATE TESTS COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
