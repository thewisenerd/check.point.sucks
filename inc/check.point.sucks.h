/*
 * copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
 *
 * license: WTFPL, http://www.wtfpl.net/txt/copying
 *
 */

#ifndef __CHECK_POINT_SUCKS_H__
#define __CHECK_POINT_SUCKS_H__ /* hehe */

#define CHECKPOINT_BASE_URL "http://127.0.0.1:5000"
#define CHECKPOINT_PORTALMAIN_URL "/PortalMain"
#define CHECKPOINT_RSASETTINGS_URL "/RSASettings"
#define CHECKPOINT_GETSTATEANDVIEW_URL "/GetStateAndView"
#define CHECKPOINT_LOGIN_URL "/Login"

#include <openssl/rsa.h>

struct checkpoint_vars_t {
	char loginToken[16+1];
	RSA *rsa;
	BIGNUM *n;
	BIGNUM *e;

	char username[15+1];
	char password[128-16 /* - padding */ + 1];
	char encrypted[128+1];
	char payload[(128*2)+1];
	char send[1024];
};

#endif /* __CHECK_POINT_SUCKS_H__ */
