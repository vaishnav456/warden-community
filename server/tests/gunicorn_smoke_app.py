"""No database/device calls: exercises the actual worker configuration."""
import threading
import time
from flask import Flask, jsonify

app = Flask(__name__)
active = threading.Event()


@app.get('/ready')
def ready():
    return jsonify(active=active.is_set())


@app.get('/slow')
def slow():
    active.set()
    time.sleep(.5)
    return jsonify(finished=True)
