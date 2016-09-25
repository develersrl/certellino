#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
from flask import Flask, render_template, request, jsonify, url_for, \
    redirect, send_file, abort, session

app = Flask(__name__)
app.config.from_envvar("CERTELLINO_SETTINGS")
app.jinja_env.add_extension('pyjade.ext.jinja.PyJadeExtension')

##################################
# CSRF protection
# http://flask.pocoo.org/snippets/3/

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.json.get('_csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(16).encode("hex")
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/')
def index():
	parms = {}

	try:
		parms["username"] = request.headers["x-auth-username"]
		parms["email"] = request.headers["x-auth-email"]
		parms["fullname"] = request.headers["x-auth-fullname"]
	except:
		if not app.debug:
			raise
		parms["username"] = "debug"
		parms["email"] = "debug@develer.com"
		parms["fullname"] = "John Debugger"

	return render_template('main.jade', **parms)

if __name__ == '__main__':
    app.run()
