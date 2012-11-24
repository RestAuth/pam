all: pam_restauth.so

pam_restauth.so: pam_restauth.c
	gcc -Wall -Werror -std=c99 -fPIC -shared -o pam_restauth.so pam_restauth.c -lcurl -lpam

install: pam_restauth.so
	cp -vp pam_restauth.so /lib/security/

uninstall:
	rm -f /lib/security/pam_restauth.so

clean:
	rm -f pam_restauth.so
