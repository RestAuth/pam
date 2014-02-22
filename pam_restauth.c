/**
 * Copyright 2012 Mihai Ghete <viper@restauth.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

#include <curl/curl.h>

#include <syslog.h>

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

/* Helper to init / reset a CURL session */
static void pam_restauth_curl_session_init(CURL *session, const char *url,
        const char *service_user, const char *service_password,
        int validate_certificate, const char *post_data) {
    curl_easy_reset(session);

    curl_easy_setopt(session, CURLOPT_NETRC, CURL_NETRC_IGNORED);
    curl_easy_setopt(session, CURLOPT_NOSIGNAL, 1L);

    curl_easy_setopt(session, CURLOPT_USERNAME, service_user);
    curl_easy_setopt(session, CURLOPT_PASSWORD, service_password);

    if (!validate_certificate)
        curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 0);

    if (post_data) {
        curl_easy_setopt(session, CURLOPT_POST, 1L);
        curl_easy_setopt(session, CURLOPT_POSTFIELDS, post_data);
    }
    else {
        curl_easy_setopt(session, CURLOPT_HTTPGET, 1L);
    }

    curl_easy_setopt(session, CURLOPT_URL, url);
}

/* RESTAuth request dispatcher */
static int pam_restauth_check(
        const char *base_url,
        const char *service_user,
        const char *service_password,
        const char *group,
        int validate_certificate,
        const char *user,
        const char *password) {

    /* allocate structures */
    CURL *session = curl_easy_init();
    char *escaped_user = url_escape(user);
    char *escaped_password = url_escape(password);
    char *url = malloc(strlen(base_url)+strlen("/users/")+strlen(user)*3+1+1);
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
    pam_restauth_curl_session_init(session, url,
                                   service_user, service_password,
                                   validate_certificate, post_data);

    /* perform request */
    int curl_http_code, curl_status = curl_easy_perform(session);
    curl_status += curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE,
                                     &curl_http_code);

    if (curl_status == CURLE_OK && curl_http_code >= 200 && curl_http_code < 300) {
        /* success. perform group check if a group is specified */
        if (group) {
            /* create group URL */
            char *escaped_group = url_escape(group);
            char *group_url = malloc(strlen(base_url)+strlen("/groups/")+strlen(escaped_group)+strlen("/users/")+strlen(escaped_user)+1);
            sprintf(group_url, "%s%sgroups/%s/users/%s/", base_url,
                    *(base_url+strlen(base_url)-1) == '/' ? "":"/",
                    escaped_group, escaped_user);

            /* set up CURL request again and perform call */
            pam_restauth_curl_session_init(session, group_url,
                                           service_user, service_password,
                                           validate_certificate, NULL);

            curl_status = curl_easy_perform(session);
            curl_status += curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE,
                                             &curl_http_code);

            if (curl_status == CURLE_OK && curl_http_code >= 200 && curl_http_code < 300) {
                ret = 0; /* success */
            }
            else {
                ret = -1; /* failure */
                syslog(LOG_AUTHPRIV|LOG_NOTICE, __FILE__": user `%s' failed RESTAuth check for group `%s'", escaped_user, escaped_group);
            }

            if (escaped_group) free(escaped_group);
            if (group_url) free(group_url);
        }
        else {
            ret = 0; /* success */
        }
    }
    else {
        ret = -1; /* failure */
    }

cleanup:
    if (session) curl_easy_cleanup(session);
    if (escaped_user) free(escaped_user);
    if (escaped_password) free(escaped_password);
    if (url) free(url);
    if (post_data) free(post_data);

    return ret;
}

static const char *string_prefix_match(const char *s, const char *prefix) {
    const char *res = strstr(s, prefix);
    if (!res || res != s)
        return res;

    return s+strlen(prefix);
}

/**
 * Returns a copy of `user' with `domain' stripped if `user' ends in domain, or NULL otherwise.
 * Returns a copy of the passed `user' if domain == NULL.
 *
 * If the result is not NULL, you will have to take care of freeing it.
 */
static char *strip_domain(const char *user, const char *domain) {
    char *stripped_username;
    size_t user_len;
    size_t domain_len;
    size_t username_len;
    
    /* basic checks */
    if (user == NULL)
        return NULL;
    
    if (domain == NULL) {
        stripped_username = malloc(strlen(user));
        return stripped_username;
    }
    
    user_len = strlen(user);
    domain_len = strlen(domain);
    username_len = user_len - domain_len;

    if (user_len < domain_len)
      return NULL; /* username cannot end with domain, abort */
    
    /* check if the last part of the loginname is the specified domain */
    if (strncmp(user+username_len, domain, domain_len) == 0) {
        /* strip the domain from the username */
        stripped_username = malloc(username_len + 1);
        strncpy(stripped_username, user, username_len);
        stripped_username[username_len] = '\0';
        
        /* return the username */
        return stripped_username;
    } else {
        /* username does not end with domain */
        return NULL;
    }
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char *argv[])
{
    const char *user;
    char *password;
    int pam_err, retry;

    const char *url = NULL;
    const char *service_user = NULL;
    const char *service_password = NULL;
    const char *group = NULL;
    const char *domain = NULL;
    int validate_certificate = 0;
    char *stripped_user = NULL;

    /* parse all parameters */
    {
        int i = 0;
        while (i < argc) {
            const char *val;

            if ((val = string_prefix_match(argv[i], "url=")) != NULL)
                url = val;
            else if ((val = string_prefix_match(argv[i], "service_user=")) != NULL)
                service_user = val;
            else if ((val = string_prefix_match(argv[i], "service_password=")) != NULL)
                service_password = val;
            else if ((val = string_prefix_match(argv[i], "group=")) != NULL)
                group = val;
            else if ((val = string_prefix_match(argv[i], "validate_certificate=")) != NULL)
                validate_certificate = !!strcmp(val, "no"); /* no = 0, everything else = 1 */
            else if ((val = string_prefix_match(argv[i], "domain=")) != NULL)
                domain = val;

            i++;
        }
    }

    /* complain about missing arguments, return error */
    if (!url || !(*url))
        syslog(LOG_AUTHPRIV|LOG_ERR, __FILE__": missing or empty required argument 'url'");
    if (!service_user)
        syslog(LOG_AUTHPRIV|LOG_ERR, __FILE__": missing required argument 'service_user'");
    if (!service_password)
        syslog(LOG_AUTHPRIV|LOG_ERR, __FILE__": missing required argument 'service_password'");

    if (!url || !(*url) || !service_user || !service_password)
        return PAM_AUTHINFO_UNAVAIL;

    /* get user */
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return (pam_err);

    /* get password - TODO why is this retry loop here? */
    for (retry = 0; retry < 3; retry++) {
        pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&password, NULL);
        if (pam_err == PAM_SUCCESS)
            break;
    }
    if (pam_err != PAM_SUCCESS)
        return (PAM_AUTH_ERR);

    /* strip domain & compare passwords */
    stripped_user = strip_domain(user, domain);
    
    if (stripped_user == NULL || pam_restauth_check(url, service_user, service_password,
                        group, validate_certificate, user, password)) {
        /* wait a bit */
        sleep(2);
        pam_err = PAM_AUTH_ERR; // TODO AUTHINFO_UNAVAIL (on hardware failure)
    } else {
        pam_err = PAM_SUCCESS;
    }
    
    if (stripped_user)
        free(stripped_user);

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
