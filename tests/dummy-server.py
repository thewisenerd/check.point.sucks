#!/usr/bin/env python

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

hashtable = (
	# dummy:dummy
	'3644550032d201edab4bb729dc4b696af95f5d4b66365cdad26bb7ef9ab514a5',
)

(pubk, privk) = rsa.newkeys(1024, exponent=0x11)
logintoken = hexlify(os.urandom(8)).decode('utf-8')

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
	global pubk, privk, logintoken

	(pubk, privk) = rsa.newkeys(1024, exponent=0x11)
	logintoken = hexlify(os.urandom(8)).decode('utf-8')

	payload = {
		'm': '%0256x' % pubk.n,
		'e': '%08x' % pubk.e,
		'loginToken': logintoken
	}

	return json.dumps(payload)

@app.route('/Login', methods=['POST'])
def login():
	global pubk, privk, logintoken, hashtable

	ret = {
		'status': 'FAILURE'
	}

	# print(request.form)

	if 'realm' not in request.form:
		return json.dumps(ret)
	if 'username' not in request.form:
		return json.dumps(ret)
	if 'password' not in request.form:
		return json.dumps(ret)

	if request.form['realm'] != 'passwordRealm':
		return json.dumps(ret)

	username = request.form['username']
	password = request.form['password']


	decrypted = rsa.decrypt(unhexlify(revStrEncode(password)), privk).decode('utf-8')
	token = decrypted[0:16]

	if (token != logintoken):
		# todo; post login expired/? here?
		# todo; keep track of time here?
		logintoken = hexlify(os.urandom(8)).decode('utf-8')
		return json.dumps(ret)

	if getsha256( username + ':' + decrypted[16:] ) in hashtable:
		ret['status'] = 'SUCCESS'

	return json.dumps(ret)

if __name__ == '__main__':
	print(pubk.n)
	print(pubk.e)
	app.run()
