/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define AGE_THRESHOLD 10  /* When pwage exceeds this, prompt for a password change */

void sighandler() {
    /* add signal handling routines here */
    /* see 'man 2 signal' */
}

int main(int argc, char* argv[]) {
    mypwent* passwddata;  /* Pointer to the user's password record from passdb */

    char important1[LENGTH] = "**IMPORTANT 1**";
    char user[LENGTH];
    char important2[LENGTH] = "**IMPORTANT 2**";

    char prompt[] = "password: ";
    char* user_pass;

    sighandler();

    while (TRUE) {
        /* Display values of important variables (for testing buffer overflows) */
        printf("Value of variable 'important1' before input of login name: %s\n", important1);
        printf("Value of variable 'important2' before input of login name: %s\n", important2);

        printf("login: ");
        fflush(NULL);         /* Flush all output buffers */
        __fpurge(stdin);      /* Purge any data in stdin buffer */

        if (fgets(user, sizeof(user), stdin) != NULL) {
            int len = strlen(user);
            if (len > 0 && user[len - 1] == '\n') {
                user[len - 1] = '\0';
                __fpurge(stdin);
            }
        }
        else {
            exit(0);
        }
   
        printf("%s", user);

        printf("Value of variable 'important1' after input of login name: %*.*s\n",
            LENGTH - 1, LENGTH - 1, important1);
        printf("Value of variable 'important2' after input of login name: %*.*s\n",
            LENGTH - 1, LENGTH - 1, important2);

        /* Get the password (using getpass() from unistd.h) */
        user_pass = getpass(prompt);
        printf("DEBUG: this is the supplied password: %s \n", user_pass);

        /* Look up the user in our password database (passdb) */
        passwddata = mygetpwnam(user);
        if (passwddata == NULL) {
            printf("User not found. Exiting.\n");
            exit(0);
        }

        /* Encrypt the user-supplied password using crypt() with the stored salt */
        char* encrypted_input = crypt(user_pass, passwddata->passwd_salt);

        if (strcmp(passwddata->passwd, encrypted_input) == 0) {
            /* Successful login */
            printf("You're in!\n");

            /* Display the number of failed login attempts, then reset them */
            printf("Number of failed login attempts: %d\n", passwddata->pwfailed);
            passwddata->pwfailed = 0;

            /* Increment the password age (i.e., count of successful logins) */
            passwddata->pwage++;

            /* If the password age exceeds the threshold, prompt the user to change the password */
            if (passwddata->pwage >= AGE_THRESHOLD) {
                printf("Your password has been used %d times.\n", passwddata->pwage);
                printf("It is recommended that you change your password.\n");

                char response[4];
                printf("Do you want to change your password now? (y/n): ");
                fflush(stdout);
                if (fgets(response, sizeof(response), stdin) != NULL) {
                    if (response[0] == 'y' || response[0] == 'Y') {
                        char* new_pass = getpass("Enter new password: ");
                        char* confirm_pass = getpass("Re-enter new password: ");
                        if (strcmp(new_pass, confirm_pass) == 0) {
                            /* Encrypt the new password with the same stored salt */
                            char* new_encrypted = crypt(new_pass, passwddata->passwd_salt);
                            /* Update the stored password (note: strdup allocates new memory) */
                            passwddata->passwd = strdup(new_encrypted);
                            /* Reset the password age after a change */
                            passwddata->pwage = 0;
                            printf("Password changed successfully. Please re-login with your new password.\n");
                        }
                        else {
                            printf("Passwords do not match. Password not changed.\n");
                        }
                    }
                    else {
                        printf("Password remains unchanged.\n");
                    }
                }
            }

            /* Update the database record with the reset failed attempts, updated password age,
               and possibly the new encrypted password */
            if (mysetpwent(passwddata->pwname, passwddata) != 0) {
                printf("Error updating password record.\n");
            }

            /* Here you might check the user's UID and launch a shell using execve(), etc. */

        }
        else {
            /* Login failed */
            printf("login failed\n");

            /* Increment the number of failed login attempts */
            passwddata->pwfailed++;
            if (mysetpwent(passwddata->pwname, passwddata) != 0) {
                printf("Error updating password record.\n");
            }
        }
    }
    return 0;
}
