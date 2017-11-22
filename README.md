check.point.sucks
=================

steps required to replicate the Check.Point. login
mechanism.

Feel free to reuse this and package into an app,
daemons, or if you're feeling bored, try brute
forcing someone's password.

```
usage: check.point.sucks [-dhksvb:p:] USER

OPTIONS
	-b, --url <URL>
		use a different base url.
	-d, --debug
		enable verbose debug messages (libcurl, json-c, openssl).
	-h, --help
		show this help message.
	-k, --insecure
		allow insecure firewalls.
	-p, --password <pass>
		pass password as an argument instead of prompt.
	-s, --skip
		skip reauth if already logged in by doing precheck.
	-v, --verbose
		be more verbose about progress.
	--no-verify
		do not verify login state after login
```

This is a very domain specific project written out
of boredom. For a more serious (probably works for you)
alternative, see https://github.com/felixb/cpfw-login

Distributed under <a href="http://www.wtfpl.net/"><img
src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
width="80" height="15" alt="WTFPL" /></a>
