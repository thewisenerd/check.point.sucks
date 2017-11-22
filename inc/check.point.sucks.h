/*
 * copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
 *
 * license: WTFPL, http://www.wtfpl.net/txt/copying
 *
 */

#ifndef __CHECK_POINT_SUCKS_H__
#define __CHECK_POINT_SUCKS_H__ /* hehe */

#define RSTR(x) (#x)
#define STR(x) RSTR(x)
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

#define CHECKPOINT_CONFIG_URL_LEN_MAX 2048-1
#define CHECKPOINT_CONFIG_USERNAME_LEN_MAX 64-1
#define CHECKPOINT_CONFIG_PASSWORD_LEN_MAX 112-1
#define CHECKPOINT_CONFIG_LOGINTOKEN_LEN 16

#define CHECKPOINT_CONFIG_PUBKEY_LEN 128

#define CHECKPOINT_CONFIG_DEFAULT_BASE_URL "http://127.0.0.1:5000"
#define CHECKPOINT_CONFIG_CURLOPT_TIMEOUT 5L
#define CHECKPOINT_CONFIG_CURLOPT_USERAGENT "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.6.01001)"

#define CHECKPOINT_CONFIG_LOGINSTR_FAILURE "FAILURE"
#define CHECKPOINT_CONFIG_LOGINSTR_SESSION_FAILURE "SESSION_FAILURE"
#define CHECKPOINT_CONFIG_LOGINSTR_AUTH_FAILURE "AUTH_FAILURE"
#define CHECKPOINT_CONFIG_LOGINSTR_SUCCESS "SUCCESS"

#define CHECKPOINT_CONFIG_VIEWSTR_FINAL "Final"
#define CHECKPOINT_CONFIG_VIEWSTR_AUTH "Authentication"

#define CHECKPOINT_CONFIG_PAYLOAD_MAX \
	  29 /* strlen("realm=passwordRealm&username=") */ \
	+ CHECKPOINT_CONFIG_USERNAME_LEN_MAX \
	+ 10 /* strlen("&password=") */ \
	+ (CHECKPOINT_CONFIG_PUBKEY_LEN*2)

#define CHECKPOINT_RSASETTINGS_URL "/RSASettings"
#define CHECKPOINT_GETSTATEANDVIEW_URL "/GetStateAndView"
#define CHECKPOINT_LOGIN_URL "/Login"

struct checkpoint_vars_t {
	unsigned int    debug;
	unsigned int  verbose;
	unsigned int insecure;
	unsigned int     skip;
	unsigned int   verify;
	char base_url[ROUND_UP(CHECKPOINT_CONFIG_URL_LEN_MAX+1, 8)];
	char username[ROUND_UP(CHECKPOINT_CONFIG_USERNAME_LEN_MAX+1, 8)];
	char password[ROUND_UP(CHECKPOINT_CONFIG_PASSWORD_LEN_MAX+1, 8)];
};

#endif /* __CHECK_POINT_SUCKS_H__ */
