/*
 * copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
 *
 * license: WTFPL, http://www.wtfpl.net/txt/copying
 *
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <curl/curl.h>
#include <json.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "check.point.sucks.h"

#define SKIP_PEER_VERIFICATION

static int _global_ret = 0;
static struct checkpoint_vars_t _global_checkpoint_vars;

int real_main(int argc, char **argv)
{
	int i, ret;
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if (!curl) {
		fputs("error instantiating curl\n", stderr);
		_global_ret = -EFAULT;
		goto exit;
	}

	_global_checkpoint_vars.rsa = RSA_new();
	if (!_global_checkpoint_vars.rsa) {
		fputs("error instantiating openssl\n", stderr);
		_global_ret = -EFAULT;
		goto exit;
	}

	memset(_global_checkpoint_vars.username, 0, 15+1);
	memset(_global_checkpoint_vars.password, 0, 256);
	strcpy(_global_checkpoint_vars.username, "dummy");
	strncpy(_global_checkpoint_vars.password+16, "dummy", strlen("dummy"));

#ifdef SKIP_PEER_VERIFICATION
	/*
	 * If you want to connect to a site who isn't using a certificate that is
	 * signed by one of the certs in the CA bundle you have, you can skip the
	 * verification of the server's certificate. This makes the connection
	 * A LOT LESS SECURE.
	 *
	 * If you have a CA cert for the server stored someplace else than in the
	 * default bundle, then the CURLOPT_CAPATH option might come handy for
	 * you.
	 */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
	/*
	 * If the site you're connecting to uses a different host name that what
	 * they have mentioned in their server certificate's commonName (or
	 * subjectAltName) fields, libcurl will refuse to connect. You can skip
	 * this check, but this will make the connection less secure.
	 */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

/* cookies */
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");

	/* get verbose debug output please */
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

/* HOP1: rsasettings */
#define HOP_URL1 CHECKPOINT_BASE_URL CHECKPOINT_RSASETTINGS_URL

	size_t curl_write_data_hop1(void *buffer, size_t size, size_t nmemb, void *userp)
	{
		json_object *json;
		json_object *t;
		int len;

		enum json_tokener_error jerr = json_tokener_success;
		json = json_tokener_parse_verbose((char*) buffer, &jerr);
		if (jerr != json_tokener_success) {
		error_parse:
			fputs("RSASettings decode error\n", stderr);
			_global_ret = -EFAULT;
			goto exit_hop1;
		}

		if (!json_object_object_get_ex(json, "loginToken", &t))
			goto error_parse;
		if (strlen(json_object_get_string(t)) != 16)
			goto error_parse;
		printf("loginToken: %s\n", json_object_get_string(t));
		strncpy(_global_checkpoint_vars.loginToken, json_object_get_string(t), 16);
		_global_checkpoint_vars.loginToken[16] = '\0';

		if (!json_object_object_get_ex(json, "m", &t))
			goto error_parse;
		if (strlen(json_object_get_string(t)) != 256)
			goto error_parse;
		printf("         m: %s\n", json_object_get_string(t));
		len = BN_hex2bn(&_global_checkpoint_vars.n, (const char*)json_object_get_string(t));
		if (len == 0)
			fprintf(stderr, "'%s' does not appear to be a valid modulus\n", json_object_get_string(t));

		if (!json_object_object_get_ex(json, "e", &t))
			goto error_parse;
		if (strlen(json_object_get_string(t)) != 8)
			goto error_parse;
		printf("         e: %s\n", json_object_get_string(t));
		len = BN_hex2bn(&_global_checkpoint_vars.e, (const char*)json_object_get_string(t));
		if (len == 0)
			fprintf(stderr, "'%s' does not appear to be a valid modulus\n", json_object_get_string(t));

		if (!RSA_set0_key(
			_global_checkpoint_vars.rsa,
			_global_checkpoint_vars.n,
			_global_checkpoint_vars.e,
			NULL
		)) {
			fprintf(stderr, "error settings rsa pubkey\n");
			_global_ret = -EFAULT;
			goto exit_hop1;
		}
		strncpy(_global_checkpoint_vars.password, _global_checkpoint_vars.loginToken, 16);

	exit_hop1:
		return size * nmemb;
	}

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data_hop1);
	curl_easy_setopt(curl, CURLOPT_URL, HOP_URL1);
	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	/* Check for errors */
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
		_global_ret = -EFAULT;
		goto exit;
	}
/* HOP1: rsasettings (end) */

/* HOP1.1: encrypt password */
	printf("dbg: %s\n", _global_checkpoint_vars.password);
	if ( (ret = RSA_public_encrypt(
		16+strlen("dummy"),
		(const unsigned char *)_global_checkpoint_vars.password,
		(unsigned char *)_global_checkpoint_vars.encrypted,
		_global_checkpoint_vars.rsa,
		 RSA_PKCS1_PADDING)
	) == -1 ) {
		fprintf(stderr, "Error encrypting message\n");
		_global_ret = -EFAULT;
		goto exit;
	}

	{
		char *msgptr = _global_checkpoint_vars.encrypted + ret - 1;
		for (i = 0; i < ret; i++) {
			snprintf(
				&_global_checkpoint_vars.payload[(2 * i)],
				3,
				"%02x",
				*(uint8_t *)msgptr
			);
			msgptr--;
		}
		_global_checkpoint_vars.payload[2*ret] = '\0';
	}

/* HOP1.1: encrypt password (end) */

	printf("\n\n------------------\n\n");

/* HOP2: meh. */
	{
#define HOP_URL2 CHECKPOINT_BASE_URL CHECKPOINT_LOGIN_URL
		int ret = 0;
		char *ptr = _global_checkpoint_vars.send;

		ret = sprintf(ptr, "realm=passwordRealm&username=dummy&password=");
		ptr += ret;
		ret += sprintf(ptr, "%s", _global_checkpoint_vars.payload);


		printf("%s; %ld\n", _global_checkpoint_vars.send, strlen(_global_checkpoint_vars.send));

		/* Now specify we want to POST data */
		curl_easy_setopt(curl, CURLOPT_POST, 1L);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);

		// curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, _global_checkpoint_vars.send);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(_global_checkpoint_vars.send));

		curl_easy_setopt(curl, CURLOPT_URL, HOP_URL2);
		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if(res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
			_global_ret = -EFAULT;
			goto exit;
		}
	}
/* HOP2: meh. (end) */

exit:
	/* always cleanup */
	curl_easy_cleanup(curl);

	curl_global_cleanup();

	BN_free(_global_checkpoint_vars.n);
	BN_free(_global_checkpoint_vars.e);

	/* TODO: handle memory leaks. a lot. */
	// RSA_free(_global_checkpoint_vars.rsa);
	return _global_ret;
}

int main(int argc, char **argv)
{
	return real_main(argc, argv);
}
