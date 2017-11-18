#!/usr/bin/env python3

#
# copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
#
# license: WTFPL, http://www.wtfpl.net/txt/copying
#

from flask import Flask
from flask import request
from flask import make_response

app = Flask(__name__)

import os
import rsa
import json
from binascii import hexlify
from binascii import unhexlify
import hashlib
import time

import collections

def currentms():
	return int(round(time.time() * 1000))

hashtable = (
	# dummy:dummy
	'3644550032d201edab4bb729dc4b696af95f5d4b66365cdad26bb7ef9ab514a5',
)

Session = collections.namedtuple('Session', 'pubk privk logintoken gentime loginok logintime')

lookuptable = {}

def getsha256(s):
	m = hashlib.sha256()
	m.update(s.encode('utf-8'))
	return hexlify(m.digest()).decode('utf-8')

def revStrEncode(s):
	if (len(s) > 2):
		s = "".join([s[i:i+2] for i in range(len(s)-2, -2, -2)])
	return s

@app.route('/RSASettings')
def rsa_settings():

	session = hexlify(os.urandom(8)).decode('utf-8')
	logintoken = hexlify(os.urandom(8)).decode('utf-8')
	(pubk, privk) = rsa.newkeys(1024, exponent=0x11)
	lookuptable[session] = Session(pubk=pubk, privk=privk, logintoken=logintoken, gentime=currentms(), loginok=False, logintime=0)

	payload = {
		'm': '%0256x' % pubk.n,
		'e': '%08x' % pubk.e,
		'loginToken': logintoken
	}

	resp = make_response(json.dumps(payload))
	resp.set_cookie('NACSID', session)

	return resp

@app.route('/Login', methods=['POST'])
def login():

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

	if 'NACSID' not in request.cookies:
		return json.dumps(failure)

	if request.cookies['NACSID'] not in lookuptable:
		return json.dumps(failure)

	if 'realm' not in request.form:
		return json.dumps(failure)
	if 'username' not in request.form:
		return json.dumps(failure)
	if 'password' not in request.form:
		return json.dumps(failure)

	if request.form['realm'] != 'passwordRealm':
		return json.dumps(failure)

	username = request.form['username']
	password = request.form['password']

	session = lookuptable[request.cookies['NACSID']]

	decrypted = rsa.decrypt(unhexlify(revStrEncode(password)), session.privk).decode('utf-8')
	token = decrypted[0:16]

	if (token != session.logintoken):
		return json.dumps(failure)

	if (currentms() - session.gentime > (250 * 1000)):
		return json.dumps(session_failure)

	if getsha256( username + ':' + decrypted[16:] ) in hashtable:
		lookuptable[request.cookies['NACSID']] = Session(pubk=session.pubk, privk=session.privk, logintoken=session.logintoken, gentime=session.gentime, loginok=True, logintime=currentms())
		return json.dumps(success)

	return json.dumps(auth_failure)

@app.route('/GetStateAndView')
def stateandview():

	ok = {
		'view': 'Final'
	}

	auth = {
		'view': 'Authentication'
	}

	if 'NACSID' not in request.cookies:
		return json.dumps(auth)

	if request.cookies['NACSID'] not in lookuptable:
		return json.dumps(auth)

	session = lookuptable[request.cookies['NACSID']]

	if session.loginok and (currentms() - session.logintime < (250 * 1000)):
		return json.dumps(ok)

	return json.dumps(auth)


if __name__ == '__main__':
	app.run()
