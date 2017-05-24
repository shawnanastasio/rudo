/**
 * C wrapper for PAM functions
 * Based off of https://stackoverflow.com/questions/32724331/authenticate-remote-user-on-linux-with-username-password-credentials
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <security/pam_appl.h>

static int pam_conv_handler(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr) {

    // Allocate empty responses for each message
    *resp = calloc(num_msg, sizeof(struct pam_response));

    int i;
    for (i=0; i<num_msg; i++) {
        // Ignore all PAM messages except prompting for hidden input
        // (implies that pam is asking for a password)
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
            continue;

        // Allocate a buffer in the response and copy the password to it
        resp[i]->resp = malloc(strlen(appdata_ptr) + 1);
        strcpy(resp[i]->resp, appdata_ptr);
    }

    return PAM_SUCCESS;
}

bool check_authentication(const char *user, const char *pass) {
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
