#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <curl/curl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif


/* utility function */
static char* url_escape(const char *str)
{
  // allocate 3 times the size of str
  char *escaped = malloc(strlen(str)*3+1);
  if (!escaped) return NULL;
  char *escaped_str = escaped;
  
  while (*str) {
    if ((*str >= 'a' && *str <= 'z') || (*str >= 'A' && *str <= 'Z') || 
	(*str >= '0' && *str <= '9'))
      *escaped_str = *str;
    else if (*str == ' ')
      *escaped_str = '+';
    else {
      *escaped_str = '%';
      *(escaped_str+1) = ((*str/16) < 10) ? ('0' + *str/16) : ('A' - 10 + *str/16);
      *(escaped_str+2) = ((*str%16) < 10) ? ('0' + *str%16) : ('A' - 10 + *str%16);
      escaped_str += 2;
    }
    
    escaped_str++;
    str++;
  }
  *escaped_str = '\0';
  
  return escaped;
}

/* RESTAuth request dispatcher */
static int pam_restauth_check(const char *base_url, const char *user, 
                              const char *password) {
  /* allocate structures */
  CURL *session = curl_easy_init();
  char *escaped_user = url_escape(user);
  char *escaped_password = url_escape(password);
  char *url = malloc(strlen(base_url)+strlen("/users/")+strlen(user)*3+1);
  char *post_data = malloc(strlen("password=")+strlen(password)*3+1);
  int ret = -1;

  if (!session || !escaped_user || !escaped_password || !url || !post_data)
    goto cleanup;

  /* create URL: <base url>/users/<user>/ */
  sprintf(url, "%s%susers/%s/", base_url, 
           *(base_url+strlen(base_url)-1) == '/' ? "":"/",
           escaped_user);

  /* create POST data: password=<password> */
  sprintf(post_data, "password=%s", escaped_password);

  /* set up CURL request */
  curl_easy_setopt(session, CURLOPT_NETRC, CURL_NETRC_IGNORED);
  curl_easy_setopt(session, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(session, CURLOPT_FAILONERROR, 1L);
  
  curl_easy_setopt(session, CURLOPT_POST, 1L);
  curl_easy_setopt(session, CURLOPT_POSTFIELDS, post_data);
  
  curl_easy_setopt(session, CURLOPT_URL, url);

  /* perform request */
  int curl_http_code, curl_status = curl_easy_perform(session);
  curl_status += curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE,
                 &curl_http_code);

  if (curl_status == CURLE_OK && curl_http_code >= 200 && curl_http_code < 300)
    ret = 0; /* success */
  else
    ret = -1; /* failure */

cleanup:
  if (session) curl_easy_cleanup(session);
  if (escaped_user) free(escaped_user);
  if (escaped_password) free(escaped_password);
  if (url) free(url);
  if (post_data) free(post_data);
  
  return ret;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    const struct pam_message *msgp;
    struct pam_response *resp;

    const char *user;
    char *password;
    int pam_err, retry;
    const char *base_url;

    /* check url */
    if (argc > 0 && *argv[0])
      base_url = argv[0];
    else
      /* base url not specified */
      return PAM_AUTHINFO_UNAVAIL;

    /* get user */
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return (pam_err);

    /* get password - TODO why is this here? */
    for (retry = 0; retry < 3; retry++) {
        pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
            (const char **)&password, NULL);

        if (pam_err == PAM_SUCCESS)
            break;
    }
    if (pam_err != PAM_SUCCESS)
        return (PAM_AUTH_ERR);

    /* compare passwords */
    if (pam_restauth_check(base_url, user, password)) {
      /* wait a bit */
      sleep(2);
      pam_err = PAM_AUTH_ERR;
    }
    else {
      pam_err = PAM_SUCCESS;
    }
    
    return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
  /* TODO implement in the future, maybe */
  return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_restauth");
#endif
