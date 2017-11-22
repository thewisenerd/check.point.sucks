/*
 * copyright (c) 2017 thewisenerd <thewisenerd@protonmail.com>
 *
 * license: WTFPL, http://www.wtfpl.net/txt/copying
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include "check.point.sucks.h"

static struct option long_opts[] = {
	{"debug",	no_argument, NULL, 'd'},
	{"help",	no_argument, NULL, 'h'},
	{"insecure",	no_argument, NULL, 'k'},
	{"skip",	no_argument, NULL, 's'},
	{"verbose",	no_argument, NULL, 'v'},
	{"no-verify",	no_argument, NULL, 128},
	{"url",		required_argument, NULL, 'b'},
	{"password",	required_argument, NULL, 'p'},
	{0, 0, 0, 0},
};

static struct checkpoint_vars_t checkpoint_vars;

extern int real_main(struct checkpoint_vars_t *vars);

int usage(void)
{
	fprintf(
		stderr,
		"usage: check.point.sucks [-dhksvb:p:] USER\n"
		"\n"
		"OPTIONS\n"

		"\t-b, --url <URL>\n"
		"\t\tuse a different base url.\n"

		"\t-d, --debug\n"
		"\t\tenable verbose debug messages (libcurl, json-c, openssl).\n"

		"\t-h, --help\n"
		"\t\tshow this help message.\n"

		"\t-k, --insecure\n"
		"\t\tallow insecure firewalls.\n"

		"\t-p, --password <pass>\n"
		"\t\tpass password as an argument instead of prompt.\n"

		"\t-s, --skip\n"
		"\t\tskip reauth if already logged in by doing precheck.\n"

		"\t-v, --verbose\n"
		"\t\tbe more verbose about progress.\n"

		"\t--no-verify\n"
		"\t\tdo not verify login state after login\n"
	);

	return EXIT_FAILURE;
}

/*
 * thanks lucas
 * https://stackoverflow.com/a/1786733
 * slight modifications for fgets and size
 *
 */
int getPassword(char *password, int size)
{
	static struct termios oldt, newt;
	int ret = 0;

	/*saving the old settings of STDIN_FILENO and copy settings for resetting*/
	tcgetattr( STDIN_FILENO, &oldt);
	newt = oldt;

	/*setting the approriate bit in the termios struct*/
	newt.c_lflag &= ~(ECHO);

	/*setting the new bits*/
	tcsetattr( STDIN_FILENO, TCSANOW, &newt);

	if (fgets(password, size, stdin) == NULL) {
		ret = -1;
	}

	/*resetting our old STDIN_FILENO*/
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

	return ret;
}

int main (int argc, char **argv)
{
	int ret;
	int longidx;

	/* zero configuration */
	memset((void *)&checkpoint_vars, 0, sizeof(struct checkpoint_vars_t));

	/* defaults */
	checkpoint_vars.verify = 1;

	while ((ret = getopt_long(argc, argv, "dhksvb:p:", long_opts, &longidx)) != -1) {
		switch(ret) {
		case 'd':
			checkpoint_vars.debug = 1;
			break;

		case 'h':
			return usage();

		case 'k':
			checkpoint_vars.insecure = 1;
			break;

		case 's':
			checkpoint_vars.skip = 1;
			break;

		case 'v':
			checkpoint_vars.verbose = 1;
			break;

		case 128:
			checkpoint_vars.verify = 0;
			break;

		case 'b':
			strncpy(checkpoint_vars.base_url, optarg, CHECKPOINT_CONFIG_URL_LEN_MAX-1);
			checkpoint_vars.base_url[CHECKPOINT_CONFIG_URL_LEN_MAX-1] = '\0';
			break;

		case 'p':
			strncpy(checkpoint_vars.password, optarg, CHECKPOINT_CONFIG_PASSWORD_LEN_MAX-1);
			checkpoint_vars.password[CHECKPOINT_CONFIG_PASSWORD_LEN_MAX-1] = '\0';
			break;

		case '?':
			/* getopt_long already printed an error message. */
			return usage();

		default:
			abort ();
		}
	}

	if (argv[optind] == NULL) {
		fputs("missing required argument(s).\n", stderr);
		return usage();
	}

	/* copy username */
	strncpy(checkpoint_vars.username, argv[optind], CHECKPOINT_CONFIG_USERNAME_LEN_MAX);
	checkpoint_vars.username[CHECKPOINT_CONFIG_USERNAME_LEN_MAX] = '\0';

	/* copy password */
	if (strlen(checkpoint_vars.password) == 0) {
		fputs("password: ", stdout);
		getPassword(checkpoint_vars.password, CHECKPOINT_CONFIG_PASSWORD_LEN_MAX+1);
		checkpoint_vars.password[strcspn(checkpoint_vars.password, "\r\n")] = '\0';
		fputc('\n', stdout);
	}

	/* copy default base url */
	if (strlen(checkpoint_vars.base_url) == 0) {
		strncpy(checkpoint_vars.base_url, CHECKPOINT_CONFIG_DEFAULT_BASE_URL, CHECKPOINT_CONFIG_URL_LEN_MAX);
		checkpoint_vars.base_url[CHECKPOINT_CONFIG_URL_LEN_MAX] = '\0';
	}

	if (strlen(checkpoint_vars.password) == 0) {
		fputs("password: did not get any password!\n", stderr);
		return -EINVAL;
	}

	if (checkpoint_vars.verbose) {
		fprintf(stdout, "verbose  : %s\n", checkpoint_vars.verbose ? "true": "false");
		fprintf(stdout, "insecure : %s\n", checkpoint_vars.insecure ? "true": "false");
		fprintf(stdout, "username : %s\n", checkpoint_vars.username);
		fprintf(stdout, "password : %s\n", checkpoint_vars.password);
		fprintf(stdout, "base url : %s\n", checkpoint_vars.base_url);
	}

	return real_main(&checkpoint_vars);
}
