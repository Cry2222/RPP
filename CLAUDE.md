# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**H@0 Checker V6.0** — a Telegram bot that validates credit cards against multiple payment gateways (Stripe, Braintree). It runs as a Flask web server on port 5000 that spawns the Telegram bot in a background thread. Access is controlled via Telegram user IDs and a redeem-key system.

## Dependencies

No `requirements.txt` exists. Install manually:

```bash
pip install aiogram aiohttp requests flask beautifulsoup4 faker urllib3
```

## Running the Project

```bash
# Primary entry point: Flask server + bot in background thread
python start.py

# Bot only (no web server)
python main.py

# Test individual gate implementations against cards in approved.txt
python test_gates.py

# Scan sites in SITES list for which gate types they support
python probe_sites.py
```

There is no build step. The project runs directly with Python.

## Environment Setup

Copy `.env.example` to `.env` and populate:

```
TELEGRAM_BOT_TOKEN=   # From @BotFather
TELEGRAM_ADMIN=       # Your Telegram numeric user ID (primary auth)
ADMIN_CODE=           # Comma-separated admin user IDs
TELEGRAM_CHAT_ID=     # (legacy) chat ID for notifications
STRIPE_PUB_KEY=       # Optional override for Stripe public key
```

Config falls back to placeholder strings if env vars are absent — the bot will start but authentication will fail.

## No Test Framework / No Linter

There is no pytest, unittest, pylint, or flake8 configuration. `test_gates.py` is a manual runner, not an automated suite. Run it to spot-check gate behavior after changes:

```bash
python test_gates.py
# Reads up to 3 cards from approved.txt (format: CC|MM|YY|CVV)
# Runs each through Stripe Charitable, Stripe Auth, Stripe Intent, Braintree Auth
```

## Architecture

### Entry & Threading

`start.py` starts Flask on `0.0.0.0:5000`, then spawns `main.py` as a subprocess in a daemon thread (1-second delay). The two processes are independent — Flask provides `/` and `/health` endpoints; the subprocess runs the full Telegram bot.

### Gate Modules

Each payment processor is an independent module. The active configuration determines which gate function is called:

| Gate type key | Module | Checker function | Auto-setup function |
|---|---|---|---|
| `stripe` | `stripe.py` | `check_stripe()` | `setup_gate_from_url()` |
| `stripe_auth` | `stripe_auth.py` | `check_stripe_auth()` | `setup_stripe_auth_from_url()` |
| `stripe_intent` | `stripe_intent.py` | `check_stripe_intent()` | `setup_stripe_intent_from_url()` |
| `braintree` | `braintree_gate.py` | `check_braintree()` | `setup_braintree_from_url()` |
| `braintree_auth` | `braintree_auth.py` | `check_braintree_auth()` | `setup_braintree_auth_from_url()` |

Each `setup_*_from_url()` function fetches the target site, scrapes keys/paths/tokens, and writes the result into the active gate config automatically. `stripe.py` also exports `detect_gate_type(url)` which scores a URL against all five gate types and returns the best match — call this before `setup_gate_from_url()` when the gate type is unknown.

`hybrid_stripe.py` and `hybrid_braintree.py` wrap their respective gates in a multi-config parallel mode toggled by the `hybrid_mode` flag in a gate config.

### Configuration System (`config.py`)

All runtime state lives in module-level dicts in `config.py` and is persisted to JSON files in `BASE_DIR`:

- **Gate configs** — each config has its own target URL, paths, keys, and gate type. Multiple configs can be active simultaneously (parallel mode).
- **Proxy pool** — `proxies_live.txt` is the working set; `proxies.txt` holds the full scraped list.
- **Redeem keys** — time-limited access tokens stored in memory and persisted to JSON.
- **User limits** — per-user card check quotas.
- **CAPTCHA settings** — provider keys and enable/disable flags.

`config.py` exports ~60 functions that `main.py` imports directly (no class instantiation).

**Gate config field schemas** (what each gate type stores):

| Field | Stripe | Braintree | Stripe Auth/Intent | Braintree Auth |
|---|---|---|---|---|
| `site_url` | ✓ | ✓ | ✓ | ✓ |
| `donate_path` | ✓ | — | — | — |
| `pub_key` / `stripe_pub_key` | ✓ | — | ✓ | — |
| `campaign_id`, `stripe_account` | ✓ | — | — | — |
| `donation_amount`, `random_amount` | ✓ | — | — | — |
| `add_to_cart_path`, `checkout_path` | — | ✓ | — | — |
| `product_payload`, `payment_method_id` | — | ✓ | — | — |
| `account_path` | — | — | ✓ | ✓ |
| `login_email`, `login_password`, `merchant_id` | — | — | — | ✓ |
| `hybrid_mode` | ✓ | ✓ | — | — |

**Parallel mode** — when enabled via `set_parallel_enabled(True)`, `main.py` calls `get_enabled_configs()` to retrieve all active configs and fans card checks out across them concurrently. Toggle with `is_parallel_enabled()` / `set_parallel_enabled()`.

### Proxy Management (`proxy_scraper.py`)

- Scrapes ~24 public proxy sources asynchronously.
- Validates live proxies concurrently; keeps a minimum of `TARGET_LIVE = 15` in `proxies_live.txt`.
- `auto_scrub_loop()` runs as a background task, refilling when pool drops below `REFILL_THRESHOLD`.
- Dead proxies are removed via `remove_dead_proxy()` after failed requests in gate modules.

### Navigating `main.py`

`main.py` is ~6,500 lines. Do not read it linearly — use `Grep` to find handlers by command name (e.g. `grep "commands=\['check'\]"`) or callback prefix (e.g. `grep "gate_"`). All Telegram command handlers are registered via `@dp.message_handler(commands=[...])` and all button callbacks via `@dp.callback_query_handler()`.

### aiogram v2/v3 Compatibility (`main.py:26–63`)

The bot detects the installed aiogram version at import time (`AIROGRAM_V3` bool). For v3, `_enable_aiogram_v2_style_handlers()` patches the dispatcher with v2-style `.message_handler()` and `.callback_query_handler()` decorators so the rest of `main.py` uses the same decoration syntax regardless of version.

### Card Flow

```
Telegram message → validate Luhn + expiry → BIN lookup (HTTP) →
select active gate config → pick proxy from pool →
gate module HTTP requests (Faker identity, human_behavior delays) →
parse response for status string → format result → Telegram reply + admin notify
```

Status values: `LIVE`, `CHARGED`, `DECLINED`, `INSUFFICIENT_FUNDS`, `3DS`, `ERROR`, `CVV`, `DEAD`.

### Human Behavior & Request Obfuscation

`human_behavior.py` provides timing functions (`human_delay`, `typing_delay`, `form_fill_delay`, `checkout_flow_delay`, etc.) that gate modules call to space out requests realistically. Gate requests use randomized User-Agent strings, fake Sec-CH-UA headers, random Stripe API versions, and Faker-generated identities.

### CAPTCHA Solving (`captcha_solver.py`)

Detects reCAPTCHA v2/v3, hCaptcha, and Cloudflare Turnstile by scraping site HTML. Submits to capsolver.com, 2captcha.com, or anticaptcha.com based on `CAPTCHA_SETTINGS`. The gate modules call into this when a challenge is detected mid-flow.

### Site Probing (`probe_sites.py`)

`probe_sites.py` is a standalone diagnostic script. Given the `SITES` list of domains, `probe_site(domain)` fetches the homepage, account page, checkout, and payment-method pages, then detects:
- Whether the site runs WooCommerce
- Whether Stripe or Braintree is present (extracts `pk_live_*` keys and merchant IDs)
- Whether add-payment-method (`stripe_auth`) or setup-intent (`stripe_intent`) flows are available
- Whether Cloudflare blocks the site

Run `python probe_sites.py` to get a summary table of which gate types each site supports — use this to populate `STRIPE_WC_SITE_POOL` / `BRAINTREE_WC_SITE_POOL` in `config.py`.

### Smart Card Generation (`smart_gen.py`)

LSTM-based generator trained on valid card BIN patterns. Called from `main.py` when a user requests generated cards. Requires `init_smart_gen()` before first use; supports `retrain` to update the model.

## Key Global State in `main.py`

- `SESSION_STATS` — dict tracking checked/live/dead/error/cycle counts across the session.
- `bot` / `dp` — global aiogram Bot and Dispatcher instances.
- User-scoped card lists and check counts are delegated to `config.py` functions.

## Data Files

| File | Purpose |
|---|---|
| `approved.txt` | Test cards (`CC\|MM\|YY\|CVV` per line) |
| `bin.txt` | BIN → issuer/country database |
| `proxies.txt` | Full scraped proxy list |
| `proxies_live.txt` | Validated working proxies (auto-managed) |
| `apis-endpoints.txt` | Additional API endpoint overrides |
