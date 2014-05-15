This is a PAM authentication plugin for [RestAuth](https://restauth.net).

# Installation

`libcurl` >= 7.19.1 and `libpam` development headers are required to compile the plugin. In the future, the [C library](https://git.fsinf.at/restauth/c-library) will be used instead of CURL.

Run:

    $ make -f Makefile.plain
    # make -f Makefile.plain install

to compile `pam_restauth.so` and copy it to `/lib/security/`, where PAM modules reside by default.

# Usage

To use the plugin, add it to the corresponding file in `/etc/pam.d/`, depending on where you want to enable RestAuth authentication on your system. See the manual for `pam.d(5)` for details or the examples section below.
At the moment, the plugin supports the following options:

* `url=<url>` (required) The URL of the RestAuth provider.
* `service_user=<username>` (required) The username used to authenticate as a [service](https://restauth.net/wiki/Specification/0.6#Service_authentication).
* `service_password=<password>` (required) The password used to authenticate as a [service](https://restauth.net/wiki/Specification/0.6#Service_authentication).
* `group=<group name>` (optional) A group the user has to belong to in order for authentication to succeed.
* `validate_certificate=yes/no` (optional, defaults to yes) Do (not) attempt to validate the SSL certificate of the RestAuth provider. If the connection to the server is done via SSL and, for some reason, you don't want to check the certificate, set this to no. Ideally, you should create a self-signed certificate and trust it on the RestAuth server instead of using this option, in case you don't have access to an already-trusted CA. Otherwise, you won't be able to guarantee the authenticity of the server and you may be the victim of a Man-in-the-middle attack. In other words, **never use this option**!
* `domain=<domain>` (optional, defaults to NULL) strips this domain from the given input and validates with the given user without this domain. The entire suffix to be stripped must be specified, including e.g. prepended `@` or `.` characters. If the username does not end with the specified domain, authentication will fail.

The options can be specified in any order. If you need to use spaces in options (e.g. for usernames with spaces), surround the affected option with square brackets. See the manual for `pam.d(5)` for specifics.

# Examples

In the examples, we assume that a service with username "vowi" and password "vowi" exists; our example RestAuth provider is located at `http://localhost:8000/`.

Your system's PAM configuration can vary by distribution. You will usually find the configuration files in `/etc/pam.d/`. Some distributions, like Ubuntu, have their own file structure in `/etc/pam.d` and extra scripts to manage aspects of PAM configuration (like `pam-auth-update(8)`). Generally however, each program (like `login`, `gnome-screensaver`, ...) has its own configuration file in `/etc/pam.d/` where you can manage per-program PAM settings.

* To allow users from group "tomato" to login on a machine using RestAuth in addition to anything else (e.g. local password), add the following to the beginning of `/etc/pam.d/login`:
        auth sufficient pam_restauth.so url=http://localhost:8000/ service_user=vowi service_password=vowi group=tomato

* To allow all users known to the RestAuth server (and no-one else) to authenticate to the Dovecot IMAP server, replace the contents of `/etc/pam.d/dovecot` with:
        auth required pam_restauth.so url=http://localhost:8000/ service_user=vowi service_password=vowi

Remember that line order in PAM configuration files is important. For the difference between "`sufficient`" and "`required`", also best read the `pam.d(5)` manual page.

# Testing

To run the unit tests (found in `tests/`), you will first need to build and install the PAM plugin on your system as outlined above. Additionally:
* Make sure a RestAuth test server is running (by executing `python setup.py testserver` in the RestAuthServer directory). Double-check that the server is listening on `http://[::1]:8000/` and has a service user configured with username `vowi` and password `vowi` (this is currently the default).
* Create the PAM service configurations in `/etc/pam.d/` as outlined in `tests/main.py`. Unfortunately, this cannot be done by the script itself (yet) as it requires root privileges.
* Make sure PyPAM and the RestAuthClient Python library are installed. You can set up a virtualenv in tests/ and run `pip install -r requirements.txt` there.
* Run `./main.py` in `tests/`. All tests should pass.

# License

The PAM plugin is licensed under the GPLv3.

# Missing features

* Integration with the C library
* Matching between Unix and RestAuth groups
* Creation of user accounts with a certain UID on first login; matching between Unix and RestAuth properties (full name, etc.)

