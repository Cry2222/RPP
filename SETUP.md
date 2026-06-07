# H@0 Checker V6.0 — Termux Setup Guide

Complete setup guide for running the Telegram card-checking bot on Android via Termux.

---

## 1. Install Termux

Download **Termux from F-Droid** (not the Play Store — the Play Store version is outdated and breaks pip installs):

👉 https://f-droid.org/en/packages/com.termux/

---

## 2. System Packages

Open Termux and run:

```bash
pkg update && pkg upgrade -y
pkg install -y python git nodejs clang make libffi openssl libjpeg-turbo
```

> `clang`, `make`, `libffi`, and `openssl` are required to compile Python packages that have C extensions (`aiohttp`, `cryptography`).

---

## 3. Clone the Repository

```bash
git clone https://github.com/Cry2222/RPP.git
cd RPP
```

---

## 4. Python Dependencies

Install all required packages:

```bash
pip install --upgrade pip
pip install aiogram aiohttp requests flask beautifulsoup4 faker urllib3
```

**Optional — needed for LSTM smart card generation:**

```bash
pip install numpy
```

> The bot starts and runs fine without `numpy`. Smart card generation falls back to a simpler random generator automatically.

> **TensorFlow is NOT available on Android/ARM** — skip it. The bot handles this automatically.

---

## 5. Node.js / js-recon (Optional — for deep gate auto-detection)

`js-recon` dramatically improves how well `setup_*_from_url()` and `probe_sites.py` detect Stripe keys and Braintree tokens by scanning JavaScript bundle files — not just visible HTML.

```bash
npm install -g @shriyanss/js-recon
```

Verify it works:

```bash
js-recon --help
```

> If `npm install -g` fails with permission errors, configure npm's global prefix:
> ```bash
> mkdir -p ~/.npm-global
> npm config set prefix ~/.npm-global
> echo 'export PATH=$HOME/.npm-global/bin:$PATH' >> ~/.bashrc
> source ~/.bashrc
> npm install -g @shriyanss/js-recon
> ```

If you skip this step the bot still works — gate setup just uses HTML-only scraping.

---

## 6. Environment Configuration

```bash
cp .env.example .env
nano .env
```

Fill in your values:

```
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
TELEGRAM_ADMIN=123456789
ADMIN_CODE=123456789
TELEGRAM_CHAT_ID=
STRIPE_PUB_KEY=
```

| Variable | How to get it |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Message [@BotFather](https://t.me/BotFather) → `/newbot` |
| `TELEGRAM_ADMIN` | Your numeric Telegram user ID — get it from [@userinfobot](https://t.me/userinfobot) |
| `ADMIN_CODE` | Same as `TELEGRAM_ADMIN` (comma-separate multiple admin IDs) |
| `TELEGRAM_CHAT_ID` | Optional — legacy notification channel |
| `STRIPE_PUB_KEY` | Optional — overrides default Stripe public key |

Save and exit nano: `Ctrl+O` → Enter → `Ctrl+X`

---

## 7. Running the Bot

### Option A — Bot only (recommended for Termux)

```bash
python main.py
```

### Option B — Bot + Flask status server on port 5000

```bash
python start.py
```

The Flask server exposes:
- `http://localhost:5000/` — liveness check
- `http://localhost:5000/health` — health check

---

## 8. Running in the Background (keep alive after closing Termux)

### Using tmux (recommended)

```bash
pkg install tmux
tmux new -s bot
python main.py
```

Detach with `Ctrl+B` then `D`. Reattach later with `tmux attach -t bot`.

### Using nohup

```bash
nohup python main.py > bot.log 2>&1 &
echo "Bot PID: $!"
```

Check logs:

```bash
tail -f bot.log
```

Stop it:

```bash
kill $(cat bot.pid)   # if you saved the PID
# or find it:
pkill -f "python main.py"
```

---

## 9. Testing Gate Configurations

Before using the bot, test that your gate configs work:

```bash
python test_gates.py
```

This reads up to 3 cards from `approved.txt` and runs them through each gate type. Cards go in `approved.txt` one per line:

```
4111111111111111|01|2026|123
5500005555555559|12|2025|456
```

---

## 10. Testing Site Auto-Detection

To scan sites and find which gate type they support:

```bash
python probe_sites.py
```

If `js-recon` is installed, it runs alongside the HTML probe for deeper detection (Stripe keys buried in JS bundles, Braintree merchant IDs, etc.).

---

## 11. Telegram Bot Commands

Once the bot is running, interact via Telegram:

| Command | What it does |
|---|---|
| `/start` | Show welcome menu |
| `/check CC\|MM\|YY\|CVV` | Check a single card |
| `/gates` | Show active gate configuration |
| `/settings` | Bot settings menu |
| `/admin` | Admin panel (owner only) |
| `/gen BIN count` | Generate cards from a BIN |
| `/redeem KEY` | Redeem an access key |

Send a `.txt` file of cards (one per line, `CC|MM|YY|CVV` format) to bulk-check.

---

## 12. Common Termux Issues

### `pip install aiohttp` fails

```bash
pkg install libffi openssl clang
pip install aiohttp
```

### `pip install numpy` fails

```bash
pkg install python-numpy
# or try pre-built:
pip install numpy --prefer-binary
```

### Port 5000 already in use

```bash
lsof -i :5000
kill -9 <PID>
```

### Bot keeps disconnecting

Use `tmux` or add Termux to your phone's battery optimization whitelist:  
Settings → Apps → Termux → Battery → Unrestricted

### `js-recon` not found after global npm install

```bash
npm config get prefix           # should show your npm prefix
ls $(npm config get prefix)/bin # should show js-recon there
export PATH=$(npm config get prefix)/bin:$PATH
```

---

## 13. File Reference

| File | Purpose |
|---|---|
| `main.py` | Telegram bot (run this) |
| `start.py` | Bot + Flask status server |
| `test_gates.py` | Manual gate tester |
| `probe_sites.py` | Site gate-type scanner |
| `.env` | Your credentials (never commit this) |
| `approved.txt` | Test cards (`CC\|MM\|YY\|CVV`) |
| `proxies_live.txt` | Auto-managed live proxy pool |
| `proxies.txt` | Full scraped proxy list |

---

## 14. Updating

```bash
git pull origin main
# re-run pip install if dependencies changed
pip install -r requirements.txt 2>/dev/null || true
```
