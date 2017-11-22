/*
 * copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
 *
 * license: WTFPL, http://www.wtfpl.net/txt/copying
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <curl/curl.h>
#include <json.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "check.point.sucks.h"

struct curl_fetch_st {
	char *memory;
	size_t size;
};

static struct checkpoint_session_vars_t {
	char loginToken[ROUND_UP(CHECKPOINT_CONFIG_LOGINTOKEN_LEN+1, 8)];
	char url[CHECKPOINT_CONFIG_URL_LEN_MAX+1];
	RSA *rsa;
	BIGNUM *n;
	BIGNUM *e;
} checkpoint_session_vars;

static size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct curl_fetch_st *mem = (struct curl_fetch_st *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
		/* out of memory! */
		fprintf(stderr, "not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

int get_rsa_settings(struct checkpoint_vars_t *vars, struct checkpoint_session_vars_t *session, CURL *curl, CURLcode *res)
{
	int ret = 0, len;
	struct curl_fetch_st fetch;

	json_object *json, *t;
	enum json_tokener_error jerr = json_tokener_success;

	/* setup URL */
	memset((void *)session->url, 0, CHECKPOINT_CONFIG_URL_LEN_MAX+1);
	strncpy(session->url, vars->base_url, CHECKPOINT_CONFIG_URL_LEN_MAX);
	strncpy(
		session->url+strlen(vars->base_url),
		CHECKPOINT_RSASETTINGS_URL,
		CHECKPOINT_CONFIG_URL_LEN_MAX-strlen(vars->base_url)
	);
	session->url[CHECKPOINT_CONFIG_URL_LEN_MAX] = '\0';
	curl_easy_setopt(curl, CURLOPT_URL, session->url);

	/* fetch curl */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
	fetch.memory = malloc(1);
	fetch.size = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&fetch);

	*res = curl_easy_perform(curl);
	if(*res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(*res));
		ret = -EFAULT;
		goto exit;
	}

	/* parse json */
	json = json_tokener_parse_verbose(fetch.memory, &jerr);
	if (jerr != json_tokener_success) {
	error_parse:
		fputs("RSASettings decode error\n", stderr);
		ret = -EFAULT;
		goto exit;
	}

	/* get loginToken */
	if (!json_object_object_get_ex(json, "loginToken", &t)) {
		if (vars->verbose)
			fputs("loginToken does not exist in RSASettings\n", stdout);
		goto error_parse;
	}
	if (strlen(json_object_get_string(t)) != CHECKPOINT_CONFIG_LOGINTOKEN_LEN) {
		if (vars->verbose)
			fprintf(stdout, "len(loginToken) != %d [%s]\n", CHECKPOINT_CONFIG_LOGINTOKEN_LEN, json_object_get_string(t));
		goto error_parse;
	}
	strncpy(session->loginToken, json_object_get_string(t), CHECKPOINT_CONFIG_LOGINTOKEN_LEN);
	session->loginToken[CHECKPOINT_CONFIG_LOGINTOKEN_LEN] = '\0';

	if (vars->verbose)
		fprintf(stdout, "loginToken: %s\n", session->loginToken);

	/* get pubkey.n */
	if (!json_object_object_get_ex(json, "m", &t)) {
		if (vars->verbose)
			fputs("m does not exist in RSASettings\n", stdout);
		goto error_parse;
	}
	if (strlen(json_object_get_string(t)) != (CHECKPOINT_CONFIG_PUBKEY_LEN*2)) {
		if (vars->verbose)
			fprintf(stdout, "len(m) != %d [%s]\n", (CHECKPOINT_CONFIG_PUBKEY_LEN*2), json_object_get_string(t));
		goto error_parse;
	}
	len = BN_hex2bn(&session->n, (const char*)json_object_get_string(t));
	if (len == 0 || len != (CHECKPOINT_CONFIG_PUBKEY_LEN*2)) {
		if (vars->verbose)
			fprintf(stderr, "error parsing m [%s]\n", json_object_get_string(t));
		goto error_parse;
	}

	/* get pubkey.e */
	if (!json_object_object_get_ex(json, "e", &t)) {
		if (vars->verbose)
			fputs("e does not exist in RSASettings\n", stdout);
		goto error_parse;
	}
	len = BN_hex2bn(&session->e, (const char*)json_object_get_string(t));
	if (len == 0) {
		if (vars->verbose)
			fprintf(stderr, "error parsing e [%s]\n", json_object_get_string(t));
		goto error_parse;
	}

	/* setup RSA key */
	session->rsa = RSA_new();
	if (session->rsa == NULL) {
		fputs("error while init RSA\n", stderr);
		ret = -EFAULT;
		goto exit;
	}

	if (!RSA_set0_key( session->rsa, session->n, session->e, NULL )) {
		fputs("error setting rsa pubkey\n", stderr);
		ret = -EFAULT;
	}

exit:
	if (fetch.memory)
		free(fetch.memory);

	return ret;
}

int do_login(struct checkpoint_vars_t *vars, struct checkpoint_session_vars_t *session, CURL *curl, CURLcode *res)
{
	int i, ret = 0, len = 0;
	struct curl_fetch_st fetch;
	json_object *json, *t, *m;
	enum json_tokener_error jerr = json_tokener_success;

	char buffer[ROUND_UP(CHECKPOINT_CONFIG_PUBKEY_LEN+1, 8)];
	char encrypted[CHECKPOINT_CONFIG_PUBKEY_LEN];
	char payload[ROUND_UP(CHECKPOINT_CONFIG_PAYLOAD_MAX+1, 8)];
	char *ptr, *enc;

	/* zero bits */
	memset((void*)buffer, 0, sizeof(buffer));
	memset((void*)encrypted, 0, sizeof(encrypted));
	memset((void*)payload, 0, sizeof(payload));

	/* encrypt: loginToken + password */
	strncpy(buffer, session->loginToken, CHECKPOINT_CONFIG_LOGINTOKEN_LEN);
	strncpy(buffer+CHECKPOINT_CONFIG_LOGINTOKEN_LEN, vars->password, CHECKPOINT_CONFIG_PUBKEY_LEN-strlen(buffer));
	buffer[CHECKPOINT_CONFIG_PUBKEY_LEN] = '\0';

	if ((len = RSA_public_encrypt(
		strlen(buffer),
		(const unsigned char *)buffer,
		(unsigned char *)encrypted,
		session->rsa,
		RSA_PKCS1_PADDING
	)) == -1) {
		fprintf(stderr, "Error encrypting message\n");
		ret = -EFAULT;
		goto exit;
	}

	if (len != CHECKPOINT_CONFIG_PUBKEY_LEN) {
		fprintf(stderr, "Error encrypting message\n");
		ret = -EFAULT;
		goto exit;
	}

	/* setup payload */
	ptr = payload;
	len = sprintf(ptr, "realm=passwordRealm&username=%s&password=", vars->username);
	ptr += len;

	enc = encrypted + CHECKPOINT_CONFIG_PUBKEY_LEN - 1;
	for (i = 0; i < CHECKPOINT_CONFIG_PUBKEY_LEN; i++) {
		snprintf(
			ptr,
			3,
			"%02x",
			*(uint8_t *)enc
		);
		ptr += 2;
		enc--;
	}
	*ptr = '\0';

	/* setup URL */
	memset((void *)session->url, 0, CHECKPOINT_CONFIG_URL_LEN_MAX+1);
	strncpy(session->url, vars->base_url, CHECKPOINT_CONFIG_URL_LEN_MAX);
	strncpy(
		session->url+strlen(vars->base_url),
		CHECKPOINT_LOGIN_URL,
		CHECKPOINT_CONFIG_URL_LEN_MAX-strlen(vars->base_url)
	);
	session->url[CHECKPOINT_CONFIG_URL_LEN_MAX] = '\0';
	curl_easy_setopt(curl, CURLOPT_URL, session->url);

	/* fetch curl */
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	fetch.memory = malloc(1);
	fetch.size = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&fetch);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));

	*res = curl_easy_perform(curl);
	if(*res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(*res));
		ret = -EFAULT;
		goto exit;
	}

	/* parse JSON */
	json = json_tokener_parse_verbose(fetch.memory, &jerr);
	if (jerr != json_tokener_success) {
	error_parse:
		fputs("Login response decode error\n", stderr);
		ret = -EFAULT;
		goto exit;
	}

	/* get type & message */
	if (!json_object_object_get_ex(json, "type", &t)) {
		if (vars->verbose)
			fputs("type does not exist in Login response\n", stdout);
		goto error_parse;
	}
	if (!json_object_object_get_ex(json, "message", &m)) {
		if (vars->verbose)
			fputs("message does not exist in Login response\n", stdout);
		goto error_parse;
	}

	if (!strcmp(CHECKPOINT_CONFIG_LOGINSTR_SUCCESS, json_object_get_string(t))) {
		if (vars->verbose)
			fputs("login success!\n", stdout);
		return 0;
	}

	fprintf(stdout, "fail: %s\n", json_object_get_string(m));

	if (!strcmp(CHECKPOINT_CONFIG_LOGINSTR_AUTH_FAILURE, json_object_get_string(t)))
		ret = -EPERM;

	if (!strcmp(CHECKPOINT_CONFIG_LOGINSTR_SESSION_FAILURE, json_object_get_string(t)))
		ret = -EINVAL;

	if (!strcmp(CHECKPOINT_CONFIG_LOGINSTR_FAILURE, json_object_get_string(t)))
		ret = -EFAULT;

exit:
	return ret;
}

int is_logged_in(struct checkpoint_vars_t *vars, struct checkpoint_session_vars_t *session, CURL *curl, CURLcode *res)
{
	int ret = 0;
	struct curl_fetch_st fetch;

	json_object *json, *t;
	enum json_tokener_error jerr = json_tokener_success;

	/* setup URL */
	memset((void *)session->url, 0, CHECKPOINT_CONFIG_URL_LEN_MAX+1);
	strncpy(session->url, vars->base_url, CHECKPOINT_CONFIG_URL_LEN_MAX);
	strncpy(
		session->url+strlen(vars->base_url),
		CHECKPOINT_GETSTATEANDVIEW_URL,
		CHECKPOINT_CONFIG_URL_LEN_MAX-strlen(vars->base_url)
	);
	session->url[CHECKPOINT_CONFIG_URL_LEN_MAX] = '\0';
	curl_easy_setopt(curl, CURLOPT_URL, session->url);

	/* fetch curl */
	curl_easy_setopt(curl, CURLOPT_POST, 0L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
	fetch.memory = malloc(1);
	fetch.size = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&fetch);

	*res = curl_easy_perform(curl);
	if(*res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(*res));
		ret = -EFAULT;
		goto exit;
	}

	/* parse json */
	json = json_tokener_parse_verbose(fetch.memory, &jerr);
	if (jerr != json_tokener_success) {
	error_parse:
		fputs("GetStateAndView decode error\n", stderr);
		ret = -EFAULT;
		goto exit;
	}

	/* get view */
	if (!json_object_object_get_ex(json, "view", &t)) {
		if (vars->verbose)
			fputs("view does not exist in GetStateAndView\n", stdout);
		goto error_parse;
	}

	if (!strcmp(CHECKPOINT_CONFIG_VIEWSTR_FINAL, json_object_get_string(t))) {
		ret = 0;
		goto exit;
	}

	ret = 1;
	if (strcmp(CHECKPOINT_CONFIG_VIEWSTR_AUTH, json_object_get_string(t))) {
		if(vars->verbose)
			fprintf(stderr, "unknown view: %s\n", json_object_get_string(t));
	}

exit:
	if (fetch.memory)
		free(fetch.memory);

	return ret;
}

int real_main(struct checkpoint_vars_t *vars)
{
	CURL *curl;
	CURLcode res;
	int ret = 0;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl) {

		/* set default timeout */
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, CHECKPOINT_CONFIG_CURLOPT_TIMEOUT);

		/* enable cookie engine */
		curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

		/* always set user agent */
		curl_easy_setopt(curl, CURLOPT_USERAGENT, CHECKPOINT_CONFIG_CURLOPT_USERAGENT);

		if (vars->debug)
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

		if (vars->insecure)
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

		if (vars->skip)
			if ( (ret = is_logged_in(vars, &checkpoint_session_vars, curl, &res)) == 0 ) {
				if (vars->verbose)
					fputs("already logged in!\n", stdout);
				goto exit;
			}

		if ( (ret = get_rsa_settings(vars, &checkpoint_session_vars, curl, &res)) )
			goto exit;

		if ( (ret = do_login(vars, &checkpoint_session_vars, curl, &res)) )
			goto exit;

		if (vars->verify) {
			ret = is_logged_in(vars, &checkpoint_session_vars, curl, &res);
			if (ret)
				fputs("unable to verify login state!\n", stderr);
		}

	exit:
		/* always cleanup */
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();

	RSA_free(checkpoint_session_vars.rsa);

	return ret;
}
