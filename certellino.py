#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
from flask import Flask, render_template, request, jsonify, \
    abort, session, make_response, safe_join
import appleprofile
import tempfile
import base64
import subprocess
from datetime import datetime

app = Flask(__name__)
app.config.from_envvar("CERTELLINO_SETTINGS")
app.jinja_env.add_extension('pyjade.ext.jinja.PyJadeExtension')
app.jinja_env.add_extension('jinja2.ext.autoescape')
app.jinja_env.autoescape = True

##################################
# CSRF protection
# http://flask.pocoo.org/snippets/3/

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token:
            abort(403)
        if request.json:
            if request.json.get('_csrf_token') != token:
                abort(403)
        else:
            if request.form.get('_csrf_token') != token:
                abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(16).encode("hex")
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def get_auth():
    auth = {}
    try:
        auth["username"] = request.headers["x-auth-username"]
        auth["email"] = request.headers["x-auth-email"]
        auth["fullname"] = request.headers["x-auth-fullname"]
    except:
        if not app.debug:
            raise
        auth["username"] = "debug"
        auth["email"] = "debug@develer.com"
        auth["fullname"] = "John Debugger"
    return auth

class CertDb(object):
    def __init__(self):
        self.db = []
        with open(app.config["CERTS_DIR"] + "/index.txt") as f:
            for L in f:
                fields = L.strip("\n").split("\t")

                tsexpire, tsrevoke, subj = fields[1],fields[2],fields[5]
                cert = {}
                for sf in subj[1:].split("/"):
                    k,v = sf.split("=",1)
                    if k == "OU" and v.startswith(r"\x00"):
                        try:
                            v = v.decode("string_escape").decode("utf_16_be")
                        except:
                            pass
                    cert[k] = v

                record = {
                    "serial": int(fields[3], 16),
                    "cert": cert,
                    "status": fields[0],
                    "expire": datetime.strptime(tsexpire[:-1], "%y%m%d%H%M%S"),

                }
                if tsrevoke:
                    record["revoke"] = datetime.strptime(tsrevoke[:-1], "%y%m%d%H%M%S")

                self.db.append(record)

    def findByEmail(self, email):
        return [rec for rec in self.db if rec["cert"]["emailAddress"] == email]

def formatSerial(serial):
    # Format a serial number in ASCII the same way OpenSSL does:
    # https://github.com/openssl/openssl/blob/26a7d938c9bf932a55cb5e4e02abb48fe395c5cd/crypto/asn1/f_int.c#L16
    # that is: an even number of hex digits
    serial = "%X" % serial
    if len(serial)%2 == 1:
        serial = "0"+serial
    return serial

def _create_cert(auth):
    tmpdir = app.config["TMPDIR"]
    where = request.json["where"]

    try:
        os.mkdir(tmpdir)
    except:
        pass

    # Generate a one-time password that will be used to encode
    # the private key.
    # NOTE: On Ubuntu, NetworkManager doesn't work with hex-encoded
    # passwords. I *think* it's because it recognizes the hex-encoding
    # and tries to outsmart the user. So we need to use a different
    # encoding; at that point, our scripts need to be swallow it
    # without errors, so the choice is limited. We use url-safe
    # base64, that contains only '-' or '_' (we strip the '=' that
    # would make the openssl scripts fail).
    password = base64.urlsafe_b64encode(os.urandom(16)).strip("=")

    # Generate the private key and certificate
    output = subprocess.check_output([
        app.config["CERTS_DIR"] + "/make_client_crt",
        auth["email"],
        auth["fullname"],
        where,
        password,
        tmpdir,
    ])
    gen = {}
    for L in output.split("\n"):
        L = L.strip()
        if not L:
            continue
        k, v = L.split(":", 1)
        gen[k] = v.strip()
    return password,gen


@app.route('/rawcert/create', methods=["POST"])
def create_raw_cert():
    auth = get_auth()
    password,gen = _create_cert(auth)

    return jsonify({
        "filename": os.path.basename(gen["zip"]),
        "password": password,
    })

@app.route('/rawcert/download')
def download_raw_cert():
    auth = get_auth()
    tmpdir = app.config["TMPDIR"]

    outfn = safe_join(tmpdir, request.args.get("filename"))
    if outfn == None or not os.path.isfile(outfn):
        abort(404)

    data = open(outfn).read()
    os.remove(outfn)

    r = make_response(data)
    r.headers["Content-Disposition"] = 'attachment; filename="%s.develer.zip"' % auth["username"]
    return r

@app.route('/pkcs12/create', methods=["POST"])
def create_pkcs12():
    auth = get_auth()
    password,gen = _create_cert(auth)

    return jsonify({
        "filename": os.path.basename(gen["client"]),
        "password": password,
    })

@app.route('/pkcs12/download')
def download_pkcs12():
    auth = get_auth()
    tmpdir = app.config["TMPDIR"]

    outfn = safe_join(tmpdir, request.args.get("filename"))
    if outfn == None or not os.path.isfile(outfn):
        abort(404)

    data = open(outfn).read()

    r = make_response(data)
    r.headers["Content-Disposition"] = 'attachment; filename="%s.develer.p12"' % auth["username"]
    r.headers["Content-Type"] = 'application/keychain_access, application/x-pkcs12'
    return r

@app.route('/appleprofile/create', methods=["POST"])
def create_apple_profile(configure_vpn=True):
    auth = get_auth()
    password,gen = _create_cert(auth)

    fd, outfn = tempfile.mkstemp(dir=app.config["TMPDIR"])
    os.close(fd)

    # It is possible to embed the password within the profile itself.
    # This is risky as it basically means that the profile is not encrypted
    # and anybody accessing it could install it.
    # We do this only on iOS because profiles are not downloaded there,
    # but directly installed. On macOS, Safari downloads them on the disk
    # first, and thus it's better to ask the user to copy the password
    # from the browser window.
    embedpassword = ""
    if request.user_agent.platform in ("iphone", "ipad"):
        embedpassword = password

    appleprofile.GenerateSignedProfile(outfn,
        signkey=app.config["APPLEPROFILE_KEY"],
        signcert=app.config["APPLEPROFILE_CERT"],
        p12cert=gen["client"],
        userid=auth["username"],
        password=embedpassword,
        servercert=gen["server"],
        ca=gen["ca"],
        configure_vpn=configure_vpn)

    return jsonify({
        "filename": os.path.basename(outfn),
        "password": password,
    })

@app.route('/oldappleprofile/create', methods=["POST"])
def create_old_apple_profile():
    return create_apple_profile(configure_vpn=False)

@app.route('/appleprofile/download')
def download_apple_profile():
    auth = get_auth()
    tmpdir = app.config["TMPDIR"]

    outfn = safe_join(tmpdir, request.args.get("filename"))
    if outfn == None or not os.path.isfile(outfn):
        abort(404)

    data = open(outfn).read()
    os.remove(outfn)

    r = make_response(data)
    r.headers["Content-Disposition"] = 'attachment; filename="%s.develer.mobileconfig"' % auth["username"]
    r.headers["Content-Type"] = 'application/x-apple-aspen-config; charset=utf-8'
    return r

@app.route('/revoke', methods=["POST"])
def revoke_cert():
    auth = get_auth()
    serial = request.json["serial"]
    try:
        serial = int(serial, 16)
    except:
        abort(404)

    # Check that the requested serial is owned by this user
    certs = CertDb()
    for c in certs.findByEmail(auth["email"]):
        if c["status"] != "V":
            # only allow to revoke valid certs
            # (not expired, nor already revoked)
            continue
        if serial == c["serial"]:
            break
    else:
        abort(404)

    # Now actually revoke it
    subprocess.check_call([
        app.config["CERTS_DIR"] + "/revoke_client_crt",
        formatSerial(serial),
    ])

    return jsonify({"success": True})

@app.route('/')
def index():
    parms = get_auth()
    parms["isapple"] = request.user_agent.platform in ("iphone", "ipad", "macos")
    parms["isappledirect"] = request.user_agent.platform in ("iphone", "ipad")
    parms["isandroid"] = request.user_agent.platform in ("android")

    certs = CertDb()
    parms["certs"] = []
    for c in certs.findByEmail(parms["email"]):
        if c["status"] != "R": # ignore revoked certs
            parms["certs"].append({
                "serial": "%04X" % c["serial"],
                "expired": datetime.today() > c["expire"],
                "expire": c["expire"].strftime("%Y-%b-%d"),
                "where": c["cert"]["OU"],
            })

    return render_template('main.jade', **parms)

if __name__ == '__main__':
    app.run()
