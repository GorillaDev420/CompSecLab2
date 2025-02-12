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
#include <stdbool.h>

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define PW_MAX_AGE 2 //for debugging

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

//Add strings to db.
//Fetch data through mypwd struct
//When fetched compare using strcmp
//Then add salt...

bool change_password(char*);
int get_user_response(void);

int main(int argc, char *argv[]) {

	mypwent* passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	bool need_update = true;
	

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
				int p = 0;
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

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			//char* salt = (char*) malloc(2 * sizeof(char));
			char* encrypted_pwd = crypt(user_pass, passwddata->passwd_salt); 
			int v1 = strcmp(passwddata->pwname, user);
			int v2 = strcmp(encrypted_pwd, passwddata->passwd);
			
			if ((v1 + v2) == 0) {
				printf("YOU ARE LOGGED IN\n");
				passwddata->pwfailed = 0;
				int age = ++passwddata->pwage;
				if(age >= PW_MAX_AGE){
					printf("Change your password\n");
					printf("[y/n]: ");
					if(get_user_response() > 0){
						need_update = change_password(user);
					}
					else{
						printf("suit yourself...\n");
					}
				}
				//"Unnecesary" code but we do not call mysetpwent twice if we have recently changed passwords
				if(need_update) mysetpwent(user, passwddata);
				need_update = true;
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			}
			else if(v2 != 0){
				passwddata->pwfailed++;
				mysetpwent(user,passwddata);
				printf("Failed logins for user: %s: %d\n",user,passwddata->pwfailed);
			}
		}
		else{
			printf("login failed\n");
		}
	
	}
	return 0;
}

int get_user_response(){
	char* response = (char*) calloc(1, sizeof(char));
	response[0] = getchar();
	if(response[0] == 'y'){
		free(response);
		return 1;
	} 
	else if(response[0] == 'n'){
		free(response);
		return 0;
	} 
	else{
		free(response);
		printf("invalid option dipshit");
		__fpurge(stdin);
		get_user_response();
	}
}

bool change_password(char* user){
	mypwent* pw = (mypwent*) malloc(sizeof(mypwent));
	char prompt_update_pwd[] = "enter old password ";
	char prompt_update_pwd2[] = "enter new password ";
	char* old_pwd;
	char* new_pwd; 
	char* encrypted;
	mypwent* oldpw = mygetpwnam(user);
	old_pwd = getpass(prompt_update_pwd);
	encrypted = crypt(old_pwd,oldpw->passwd_salt);
	int v = strcmp(encrypted, oldpw->passwd);
	int flag = 0;
	printf("\n");
	if(v == 0){
		new_pwd = getpass(prompt_update_pwd2);
		pw->passwd = crypt(new_pwd, "ST");
		pw->pwage = 0;
		pw->pwfailed = 0;
		pw->passwd_salt = "ST";
		pw->pwname = user;
		mysetpwent(user, pw);
		printf("update db...\n");
		free(pw);
		return false;
	}
	free(pw);
	printf("couldnt change password");
	return true;
}
