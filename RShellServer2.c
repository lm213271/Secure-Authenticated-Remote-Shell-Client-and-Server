#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>

struct Msg{
    char msgtype;
    short paylen;
    char id[16];
    char *payload;
};

struct Msg * read_client_msg(int sock){

    struct Msg *msg = (struct Msg*)(malloc(sizeof(struct Msg)));
    int read_id;
    int read_payload;
   
    // read message type
    int read_type = read(sock, &msg->msgtype, 1);

    // read message length
    int read_length = read(sock, &msg->paylen, 2);

    // read message id
    if (msg->paylen >= 16) {
        read_id = read(sock, &msg->id, 16);
    }
    // read message payload
    if (msg->paylen > 16) {
        msg->payload = (char*)malloc( (msg->paylen - 16) * sizeof(char));
        read_payload = read(sock, msg->payload, (msg->paylen - 16) );
    }
   
    // Check for errors
    if (read_type != 1){
        printf("\nClient disconnected from Server.\n");
        free(msg);
        return NULL;
    }
    if (read_length != 2){
        printf("\nERROR: Invalid  message length.\n");
        free(msg);
        return NULL;
    }
    if ( read_id != 16 ){
            printf("\nERROR: Invalid message id.\n");
            free(msg);
            return NULL;
    }
    if ( read_payload != (msg->paylen - 16) ){
            printf("\nERROR: Invalid  message payload.\n");
            free(msg);
            return NULL;
    }
    return msg;
}


int write_msg_to_client(int sock, struct Msg *msg){

    int type_size = 1;
    int length = 2;
	int value;
    // write message type 
    int write_type = write(sock, &msg->msgtype, type_size);

    // write the message length
    int write_length = write(sock, &msg->paylen, length);

    int write_id;
    int write_payload;

    // write the id
    if (msg->paylen >= 16) {
        write_id = write(sock, &msg->id, 16);
    }
    // write the payload
    if (msg->paylen > 17) {
        write_payload = write(sock, msg->payload, (msg->paylen - 16) );
    }

    // Check for errors   
    if ( write_type != 1 ){
        printf("ERROR: Invalid message type size...\n");
        printf("Trying to send message with %d byte while the size of message('%s') type should be %d byte\n", write_type, &msg, 1);
        close(sock);
        value = -1;
    }
    if ( write_length != 2){
        printf("ERROR: Invalid message length...\n");
        printf("Trying to send message with %d byte length while the message('%s') length should be %d bytes\n", write_length, &msg, 2);
        close(sock);
        value = -1;
    }
    if ( write_id != 16 ){
            printf("ERROR: Invalid message id...\n");
            printf("Trying to send id with %d bytes while the message('%s') id size should be %d bytes\n", write_id, &msg, 16);
            close(sock);
            value = -1;
    }
    if ( write_payload != (msg->paylen - 16) ){
            printf("ERROR: Invalid message payload size...\n");
            printf("Trying to send payload with %d bytes while the message('%s') payload size should be %d\n", write_payload, &msg, (msg->payload - 16)); 
           close(sock);
            value =  -1;
    }
    value = 0;
	return value;
}

			

int
serversock(int UDPorTCP, int portN, int qlen)
{
    struct sockaddr_in svr_addr;    /* my server endpoint address       */
    int    sock;            /* socket descriptor to be allocated    */

    if (portN<0 || portN>65535 || qlen<0)   /* sanity test of parameters */
        return -2;

    bzero((char *)&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
    svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
    sock = socket(PF_INET, UDPorTCP, 0);
    if (sock < 0)
        return -3;

    /* Bind the socket */
    if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
        return -4;

    if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
        return -5;

    return sock;
}

inline int serverTCPsock(int portN, int qlen)
{
  return serversock(SOCK_STREAM, portN, qlen);
}

inline int serverUDPsock(int portN)
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void usage(char *self)
{
    // Useage message when bad # of arguments
    fprintf(stderr, "Usage: %s <port to run server on> <password file> \n", self);
    exit(1);
}

void errmesg(char *msg)
{
    fprintf(stderr, "**** %s\n", msg);
    exit(1);

}

void
reaper(int signum)
{
/*
    union wait  status;
*/

    int status;

    while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
        /* empty */;
}

int main(int argc, char *argv[])
{
    int  portN;   
    char *cmdline;
    char *cmdline2;
    char userId[16];
    unsigned char ptext [128];
    unsigned char ctext [128];
	char msg_result1[65535];

    if (argc == 3){
        portN = atoi(argv[1]);
        cmdline = argv[2];
    }else{
        usage(argv[0]);
    }

	char msg_result2[65535];
	EVP_CIPHER_CTX ctx; 
	unsigned char* iv = (unsigned char*) "0123456789012345";
   	unsigned char* key = (unsigned char*) "a68d1818922322ebbac5272b1b8013962e092a76";
   	unsigned char *iv2 = (unsigned char *)"0123456789012345";
   	unsigned char *key2 = (unsigned char *)"a68d1818922322ebbac5272b1b8013962e092a76";
   	unsigned char *iv3 = (unsigned char *)"0123456789012345";
    unsigned char *key3 = (unsigned char *)"a68d1818922322ebbac5272b1b8013962e092a76";
	unsigned char ctxt2[128];
	unsigned char ctxt3[128];
  	
	int ctxt_len2;
	int ctxt_len3;
	int ptext_len;	
	int ctext_len;
	int msg_result_size = 65535;
	size_t numlines = 0;
	ssize_t getpw;	

    char nounce1_string[50];
    char * pointer2;
    long en_nonce1;
    long en_nonce2 = 64;
    long de_nonce2;
    char nonce2_string[50];
    sprintf(nonce2_string,"%ld",en_nonce2);

	FILE *fp1;
	FILE *fp2;
	FILE *pw = NULL;
    struct Msg *message;
    struct timeval atime;
    struct timeval rtime;

    bool authenticated = false;
	bool is_authenticated = false;

    char * pointer;
	char* buffer;
	char * username;
	char *c = NULL;

    int  server_tcb;         
    int  sock;              
    struct sockaddr_in distenation;    
    unsigned int  dist_len;     

    server_tcb = serverTCPsock(portN, 5);

    (void) signal(SIGCHLD, reaper);

    while (1) {
        dist_len = sizeof(distenation);
        sock = accept(server_tcb, (struct sockaddr *)&distenation, &dist_len);
        if (sock < 0) {
            if (errno == EINTR) { 
                continue;
            }
            errmesg("accept error\n");
        }
		if(fork() == 0) {
            close(server_tcb);

            printf("Client connected to Server Successfully.\n");

            while(message = read_client_msg(sock)){
                if(message){
                    printf("\n***************************************************\n");
                    printf("Client message received with following informations:\n");
                    printf("\nMESSAGE--> TYPE: 0x0%d\n", message->msgtype);
                    printf("PAYLEN: %d\n", message->paylen);
                    printf("ID: %s\n", message->id);
                    printf("PAYLOAD: %s\n", message->payload);
                    printf("***************************************************\n\n");

                    gettimeofday(&rtime,NULL);
                    if( (rtime.tv_sec - atime.tv_sec) > 60){
                        printf("60 second authentication period has passed.\n\n");
                        authenticated = false;
                    }

                    if(authenticated == false){
                        if (message->msgtype == 0x1) {
                      
                         	strcpy(nounce1_string,message->payload);
                           	nounce1_string[(message->paylen - 16) ] = '\0';

                          	printf("nonce1 send by client is: %s\n\n", nounce1_string);

                           	memcpy(userId,message->id, 16);

                           	userId[strlen(userId)] = '\0';
                        	free(message);

                        	message = malloc(sizeof(struct Msg));
                        	message->msgtype = 0x2;
                        	message->paylen = 16 + 4;
                        	memcpy(message->id,userId,(16 - 1));
                        	message->id[strlen(userId)] = '\0';
                        	message->payload = nonce2_string;

                        	printf("\n********************************************************************\n");
                        	printf("Sending Message to Client from Server with the following information:\n");
                        	printf("\nMESSAGE--> TYPE: 0x0%d\n", message->msgtype);
                        	printf("PAYLEN: %d\n", message->paylen);
                        	printf("ID: %s\n", message->id);
                        	printf("PAYLOAD: %s\n", message->payload);
                        	printf("********************************************************************\n\n");
                        	write_msg_to_client(sock, message);
                        }
						if (message->msgtype == 0x3) {

                        	strcpy(ctext,message->payload);
 
						    EVP_CIPHER_CTX *ctx;
    						ctx = EVP_CIPHER_CTX_new();

    						int ptxtlen, length;

    						EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    						EVP_DecryptUpdate(ctx, ptext, &length, ctext, strlen(message->payload));
    						ptxtlen = length;

    						EVP_DecryptFinal_ex(ctx, ptext+length, &length);
    						ptxtlen += length;

    						ptext_len = ptxtlen;

	                       	ptext[ptext_len] = '\0';
                        	printf("Decrypted command ---> %s\n\n", ptext);

                        	de_nonce2 = strtol(ptext, &pointer, 10) - 1;
                        
                        	cmdline2 = (char*)malloc((strlen(ptext) - strlen(nonce2_string)) *  sizeof(char) + 1);
                        
                        	sprintf(cmdline2,"%s",pointer);
                        	cmdline2[strlen(cmdline2)] = '\0';
                        	printf("\n%s wants to run %s command\n\n", userId, cmdline2);
    						pw = fopen(cmdline, "r");

    						if (pw == 0){
        						printf("ERROR: Counldn't open passwdfile\n");

								exit(1);
    						}else{
        						getpw = getline(&c, &numlines, pw);

        						fclose(pw);

        						buffer = strtok(c, ";");
        						memcpy(&username, &buffer, sizeof(username));

        						if(strcmp(userId, username) == 0){
									printf("\nIDs matched: Authentication Success\n");
                					free(c);
               						is_authenticated = true;
        						}else{
            						printf("ID mismatched\n\n");
									is_authenticated = false;
        						}
    						}

                        	if((is_authenticated ) ) {
								if (en_nonce2 == de_nonce2) {
                	            	en_nonce1 = strtol(nounce1_string, &pointer2, 10);
            	                	en_nonce1 = en_nonce1 + 1;
        	                    	sprintf(nounce1_string,"%ld",en_nonce1);
                            	
   		 							EVP_CIPHER_CTX *ctx;
	    							ctx = EVP_CIPHER_CTX_new();
    								int ctxtlen, length;

    								EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    								EVP_EncryptUpdate(ctx, ctext, &length, nounce1_string, strlen ((char *)nounce1_string));
    								ctxtlen = length;
    								EVP_EncryptFinal_ex(ctx, ctext+length, &length);
    								ctxtlen += length;
    								EVP_CIPHER_CTX_free(ctx);
									
									ctext_len = ctxtlen;

									authenticated = true;
                            		gettimeofday(&atime,NULL);
                        	    	free(message);

                    	        	message = malloc(sizeof(struct Msg));
                	            	message->msgtype = 0x4;
            	                	message->paylen = 16 + ctext_len + 1;
        	                    	memcpy(message->id,userId,(16 - 1));
    	                        	message->id[strlen(userId)] = '\0';
	                            	ctext[ctext_len] = '\0';
                            		message->payload = ctext;

                            		printf("\n********************************************************************\n");
                        	    	printf("Sending Message to Client from Server with the following information:\n");
                    	        	printf("\nMESSAGE--> TYPE: 0x0%d\n", message->msgtype);
                	           	 	printf("PAYLEN: %d\n", message->paylen);
            	                	printf("ID: %s\n", message->id);
        	                    	printf("PAYLOAD:% s\n", message->payload);
    	                        	printf("********************************************************************\n\n");

	                            	write_msg_to_client(sock, message);
	
    	                        	free(message);

        	                	    printf("The RShell command to be run on the Server is: %s\n\n", cmdline2);

    								memset(msg_result1, 0, 65535);
								    struct Msg *shellmsg = (malloc(sizeof(struct Msg)));
								    if ((fp1 = popen(cmdline2, "r")) == NULL){
    								    shellmsg = NULL;
 								   	}

								    strcat(cmdline2, " 2>&1");
								    fread(msg_result1, 65535, 1, fp1); 
								    pclose(fp1);
	    							msg_result1[strlen(msg_result1) - 1] = '\0';
    							
                                	ctx = EVP_CIPHER_CTX_new();

                            	    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key2, iv2);
                        	        EVP_EncryptUpdate(ctx, ctxt2, &length, msg_result1, strlen ((char *)msg_result1));
                    	            ctxtlen = length;
                	                EVP_EncryptFinal_ex(ctx, ctxt2+length, &length);
            	                    ctxtlen += length;
        	                        EVP_CIPHER_CTX_free(ctx);		
					
									ctxt_len2 = ctxtlen;
	
									shellmsg->msgtype = 0x6;
    								shellmsg->paylen = 16 + ctxt_len2;
	   								 memcpy(shellmsg->id,userId,(16 - 1));
    								shellmsg->id[strlen(userId)] = '\0';
    								ctxt2[ctxt_len2] = '\0';
    								shellmsg->payload = ctxt2;

    								printf("The result from command '%s' was:\n%s\n\n", cmdline2, msg_result1);

									message = shellmsg;
                            	
									printf("\n********************************************************************\n");
        	                    	printf("Sending Message to Client from Server with the following information:\n");
    	                        	printf("\nMESSAGE--> TYPE: 0x0%d\n", message->msgtype);
	                            	printf("PAYLEN: %d\n", message->paylen);
                            		printf("ID: %s\n", message->id);
                            		printf("PAYLOAD: %s\n", message->payload);
                            		printf("********************************************************************\n\n");
    	                        	write_msg_to_client(sock, message);
        	                	    free(message);
            	            	    free(cmdline2);
                            	}
							}
							else{   
                                authenticated = false;

                                free(message);
                                message = malloc(sizeof(struct Msg));
                                message->msgtype = 0x5;
                                message->paylen = 16 + strlen(nounce1_string) + 1;
                                memcpy(message->id,userId,( 15));
                                message->id[strlen(userId)] = '\0';
                                message->payload = nounce1_string;
                                printf("\n********************************************************************\n");
                                printf("Sending Message to Client from Server with the following information:\n");
                                printf("\nMESSAGE--> TYPE: 0x0%d\n", message->msgtype);
                                printf("PAYLEN: %d\n", message->paylen);
                                printf("ID: %s\n", message->id);
                                printf("PAYLOAD: %s\n", message->payload);
                                printf("********************************************************************\n\n");

                                write_msg_to_client(sock, message);
                            }
                     	}
                 		else {
                        	printf("ERROR: Invalid message received.\n");
                      	}
                 	}
					else{
                      	printf("User %s Authentication Successful\nRun command now...\n\n", userId);
                      	if (message -> msgtype == 0x1){

                     		cmdline2 = (char*)malloc( (message->paylen - 16) * sizeof(char));
                      		memcpy(cmdline2, message->payload, strlen(message->payload));
                        	cmdline2[(message->paylen - 16) ] = '\0';
                     		memcpy(userId,message->id,16);
                           	userId[strlen(userId)] = '\0';
                        	printf("Client ID: %s\n", userId);
                         	free(message);

                           	printf("Comand that RShell will run is --->  %s\n\n", cmdline2);

						    memset(msg_result2, 0, 65535);

   							struct Msg *shellmsg = (malloc(sizeof(struct Msg)));

   							if ((fp2 = popen(cmdline2, "r")) == NULL){
        							shellmsg = NULL;
    						}
		
    						printf("");
    						strcat(cmdline2, " 2>&1");
    						fread(msg_result2, 65535, 1, fp2); 
    						pclose(fp2);

    						msg_result2[strlen(msg_result2) - 1] = '\0';

							EVP_CIPHER_CTX *ctx;
                           	ctx = EVP_CIPHER_CTX_new();
                       	    int ctxtlen, length;

                   	        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key3, iv3);
               	            EVP_EncryptUpdate(ctx, ctxt3, &length, msg_result2, strlen ((char *)msg_result2));
              	            ctxtlen = length;
             	           	EVP_EncryptFinal_ex(ctx, ctxt3+length, &length);
                       	   	ctxtlen += length;
                            EVP_CIPHER_CTX_free(ctx);
                    
                            ctxt_len3 = ctxtlen;

							shellmsg->msgtype = 0x6;
    						shellmsg->paylen = 16 + ctxt_len3;
    						memcpy(shellmsg->id,userId, (16 - 1));
    						shellmsg->id[strlen(userId)] = '\0';
    						ctxt3[ctxt_len3] = '\0';
   							shellmsg->payload = ctxt3;

    						printf("The result from command '%s' was:\n%s\n\n", cmdline2, msg_result2);

							message = shellmsg;


                         	printf("\n********************************************************************\n");
                         	printf("Sending Message to Client from Server with the following information:\n");
                          	printf("\nMESSAGE--> TYPE: 0x0%d\n", message->msgtype);
                          	printf("PAYLEN: %d\n", message->paylen);
                   	        printf("ID: %s\n", message->id);
           	                printf("PAYLOAD: %s\n", message->payload);
       	                  	printf("********************************************************************\n\n");

                          	write_msg_to_client(sock, message);       
                       		free(message);
							free(cmdline2);
						}
                        else {     
                           	printf("ERROR: Invalid message received.\n");
                    	}      
                 	}
              	}
           	}
      	
         	close(sock);
         	exit(1);
		}
        else{   
         	(void) close(sock);
        }
    }
    close(server_tcb);
}

