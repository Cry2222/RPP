from flask import Flask
from threading import Thread

app = Flask('')

@app.route('/')
def home():
    from flask import make_response
    resp = make_response("Bot is online and scrubbing 24/7!")
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/health')
def health():
    from flask import make_response
    resp = make_response("OK")
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

def run():
    app.run(host='0.0.0.0', port=5000)

def live():
    t = Thread(target=run)
    t.daemon = True
    t.start()
