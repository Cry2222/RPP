from flask import Flask, request, send_from_directory
from threading import Thread
import os
import subprocess

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

@app.route('/curl.php')
def run_php():
    lista = request.args.get('lista', '')
    if not lista:
        return "No list provided", 400
    
    # Execute PHP script and return output
    process = None
    try:
        # Use simple 'php' command if in path, or absolute path
        php_cmd = 'php' 
        # Pass lista as the first argument to PHP script
        # Using shell=False for security, passing as argument
        process = subprocess.Popen([php_cmd, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'curl.php'), lista], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=30)
        
        if process.returncode != 0:
            return f"PHP Execution Error: {stderr}", 500
            
        return stdout
    except subprocess.TimeoutExpired:
        if process:
            process.kill()
        return "PHP Execution Timeout", 504
    except Exception as e:
        return f"System Error: {str(e)}", 500

def run():
    app.run(host='0.0.0.0', port=5000)

def live():  
    t = Thread(target=run)
    t.daemon = True
    t.start()
