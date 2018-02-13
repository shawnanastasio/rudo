/**
 * C wrapper for PAM functions
 * Based off of https://stackoverflow.com/questions/32724331/authenticate-remote-user-on-linux-with-username-password-credentials
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <security/pam_appl.h>

static int pam_conv_handler(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr) {

    // Validate num_msg
    if (num_msg > PAM_MAX_NUM_MSG) {
        return PAM_CONV_ERR;
    }

    // Allocate empty responses for each message
    struct pam_response *responses = calloc(num_msg, sizeof(struct pam_response));
    if (!responses) {
        // If the allocation failed, return PAM_BUF_ERR
        return PAM_BUF_ERR;
    }
    *resp = responses;

    int i;
    for (i=0; i<num_msg; i++) {
        // Ignore all PAM messages except prompting for hidden input
        // (implies that pam is asking for a password)
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
            continue;

        // Allocate a buffer in the response and copy the password to it
        responses[i].resp = malloc(strlen(appdata_ptr) + 1);
        if (!responses[i].resp) {
            // If the allocation failed, free all allocations and return PAM_BUF_ERR;
            while (i-- > 0) {
                free(responses[i].resp);
            }
            free(responses);
            return PAM_BUF_ERR;
        }
        strcpy(responses[i].resp, appdata_ptr);
    }

    return PAM_SUCCESS;
}

bool check_authentication(const char *user, const char *pass) {
    // Validate the length of the given password
    size_t pass_len = strlen(pass);
    if (pass_len > PAM_MAX_MSG_SIZE - 1 || pass_len < 1) {
        return false;
    }

    // Create a pam conversation struct using our handler above
    struct pam_conv conv = { &pam_conv_handler, (void *)pass };

    pam_handle_t *handle;
    int authResult;

    pam_start("rudo", user, &conv, &handle);
    authResult = pam_authenticate(handle,
            PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
    pam_end(handle, authResult);

    return (authResult == PAM_SUCCESS);
}
