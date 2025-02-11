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
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

//Add strings to db.
//Fetch data through mypwd struct
//When fetched compare using strcmp
//Then add salt...

int main(int argc, char *argv[]) {

	mypwent* passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";


	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */


		if (fgets (user, sizeof(user), stdin) != NULL){
			int len = strlen(user); /* gets() is vulnerable to buffer */
			if (len > 0 && user [len-1] == '\n') {
				user[len-1] = '\0';
				__fpurge(stdin);
			}
			
		}
		else{
			exit(0);
		}
		printf (user);
		/*  overflow attacks.  */
	
		//remove \n

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);
		user_pass = getpass(prompt);
		printf("DEBUG: this is the supplied password: %s \n",user_pass);
		passwddata = mygetpwnam(user);
		if (passwddata==NULL)
		{
			printf("null exit");
			exit(0);
		}
		int v1 = strcmp(passwddata->pwname, user);
		int v2 = strcmp(passwddata->passwd, user_pass);
		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			if ((v1 + v2) == 0) {

				printf(" You're in  !\n");

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			}
			else{
				printf("login failed\n");
			}
		}
	
	}
	return 0; }