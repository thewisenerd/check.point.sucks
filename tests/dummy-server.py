#!/usr/bin/env python3

#
# copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
#
# license: WTFPL, http://www.wtfpl.net/txt/copying
#

from flask import Flask
from flask import request

app = Flask(__name__)

import os
import rsa
import json
from binascii import hexlify
from binascii import unhexlify
import hashlib
import time

def currentms():
	return int(round(time.time() * 1000))

hashtable = (
	# dummy:dummy
	'3644550032d201edab4bb729dc4b696af95f5d4b66365cdad26bb7ef9ab514a5',
)

(pubk, privk) = rsa.newkeys(1024, exponent=0x11)
logintoken = hexlify(os.urandom(8)).decode('utf-8')
gentime = currentms()
(loginok, logintime) = (False, 0)

def getsha256(s):
	m = hashlib.sha256()
	m.update(s.encode('utf-8'))
	return hexlify(m.digest()).decode('utf-8')

def revStrEncode(s):
	if (len(s) > 2):
		s = "".join([s[i:i+2] for i in range(len(s)-2, -2, -2)])
	return s

@app.route('/GetStateAndView')
def stateandview():
	global loginok, logintime

	ok = {
		'view': 'Final'
	}

	auth = {
		'view': 'Authentication'
	}

	if loginok and (currentms() - logintime < (250 * 1000)):
		return json.dumps(ok)

	return json.dumps(auth)

@app.route('/RSASettings')
def rsa_settings():
	global pubk, privk, logintoken, gentime, loginok, logintime

	(pubk, privk) = rsa.newkeys(1024, exponent=0x11)
	logintoken = hexlify(os.urandom(8)).decode('utf-8')
	gentime = currentms()
	loginok = False

	payload = {
		'm': '%0256x' % pubk.n,
		'e': '%08x' % pubk.e,
		'loginToken': logintoken
	}

	return json.dumps(payload)

@app.route('/Login', methods=['POST'])
def login():
	global pubk, privk, logintoken, gentime, hashtable, loginok, logintime

	loginok = False

	auth_failure = {
		"context":"",
		"type":"AUTH_FAILURE",
		"message":"Username or password incorrect",
		"opaque":"",
		"nextStateId":""
	}

	failure = {
		"context":"",
		"type":"FAILURE",
		"message":"Login failed. If the problem persists please contact your administrator",
		"opaque":"",
		"nextStateId":""
	}

	session_failure = {
		"context":"",
		"type":"SESSION_FAILURE",
		"message":"Your session has expired. Please try again",
		"opaque":"",
		"nextStateId":""
	}

	success = {
		"context":"",
		"type":"SUCCESS",
		"message":"",
		"opaque":"",
		"nextStateId":"",
		"orgUrl":"",
		"keepAliveActive":False,
		"delayInterval":"250"
	}

	if 'realm' not in request.form:
		return json.dumps(ret)
	if 'username' not in request.form:
		return json.dumps(ret)
	if 'password' not in request.form:
		return json.dumps(ret)

	if request.form['realm'] != 'passwordRealm':
		return json.dumps(failure)

	username = request.form['username']
	password = request.form['password']

	decrypted = rsa.decrypt(unhexlify(revStrEncode(password)), privk).decode('utf-8')
	token = decrypted[0:16]

	if (token != logintoken):
		return json.dumps(failure)

	if (currentms() - gentime > (250 * 1000)):
		return json.dumps(session_failure)

	if getsha256( username + ':' + decrypted[16:] ) in hashtable:
		loginok = True
		logintime = currentms()
		return json.dumps(success)

	return json.dumps(auth_failure)

if __name__ == '__main__':
	app.run()
