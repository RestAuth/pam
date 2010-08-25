all: pam_restauth.so

pam_restauth.so: pam_restauth.c
	gcc -shared -o pam_restauth.so pam_restauth.c -lcurl -lpam

clean:
	rm -f pam_restauth.so
