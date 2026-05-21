import os
import sys
import subprocess
import time
from threading import Thread

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def home():
    resp = make_response("H@0 Checker V6.0 - Online")
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/health')
def health():
    resp = make_response("OK")
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

def run_bot():
    time.sleep(1)
    subprocess.call([sys.executable, "main.py"])

if __name__ == '__main__':
    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()
    app.run(host='0.0.0.0', port=5000)
