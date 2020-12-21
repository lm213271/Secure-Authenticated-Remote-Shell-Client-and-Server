
#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
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

int aes_256_Encrypt(unsigned char *ctxt, unsigned char *ptxt, int ptxt_len, unsigned char *key, unsigned char* iv) 
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int ctxt_len;
	ctx = EVP_CIPHER_CTX_new();
   	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, ctxt, &length, ptxt, ptxt_len);
    ctxt_len = length;
	EVP_EncryptFinal_ex(ctx, ctxt + length, &length);
    ctxt_len += length;
    EVP_CIPHER_CTX_free(ctx);

    return ctxt_len;
}

int aes_256_Decrypt(unsigned char *ptxt,unsigned char *ctxt, int ctxtlen, unsigned char *key, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int ptxt_len;
	ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, ptxt, &length, ctxt, ctxtlen);

    ptxt_len = length;
	EVP_DecryptFinal_ex(ctx, ptxt + length, &length);
    ptxt_len += length;

    return ptxt_len;
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
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1)
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}

inline int clientTCPsock(const char *destination, int portN)
{
  return clientsock(SOCK_STREAM, destination, portN);
}


inline int clientUDPsock(const char *destination, int portN)
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


void usage(char *self)
{
	// Useage message when bad # of arguments
	fprintf(stderr, "Usage: %s <server IP> <server port number> <ID> <password> \n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf
 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0;
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;


	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n",
			   sock, buflen, flag, n, buf);

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;


		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n",
			   sock, buflen, flag, n, &buf[inbytes]);


	  if (n<=0) /* no more bytes to receive */
		break;
	};


		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n",
			   sock, buflen, inbytes, buf);


	return inbytes;
}

int
RemoteShell(char *destination, int portN)
{
	char	buf[65519+1];		/* buffer for one line of text	*/
	char	result[65536];
	int	sock;				/* socket descriptor, read count*/


	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin))
	{
		buf[65519] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{

			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n",
			   destination, portN, n, outchars, buf);

			close(sock);
			return -1;
		}

		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n",
			   destination, portN, n, buf);


		/* Get the result */

		if ((inchars=recv(sock, result, 65535, 0))>0) /* got some result */
		{
			result[inchars]=0;
			fputs(result, stdout);
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int
main(int argc, char *argv[])
{

	/* Variables */
	char *destination;
	int portN;
	int sock;
	char *user;
	char* pwd;
	SHA_CTX ctx;
	unsigned char hash1[SHA_DIGEST_LENGTH];
    unsigned char hash2[SHA_DIGEST_LENGTH];

	struct Msg *message;
	struct Msg *server_msg;
	struct Msg* receivedmsg;

	unsigned char ctxt[128];
    unsigned char ptxt[128];
    char Buffer[65520];
	unsigned char Pw[SHA_DIGEST_LENGTH * 2];
	unsigned char k[SHA_DIGEST_LENGTH * 2];
	unsigned char *iv = (unsigned char *)"0123456789012345";

	char* pointer;
	long nonce1Val = 32;
    long nonce2Val;
    long nonce1Val2;	
	char nonce1_string [50];
	char nonce2_string[50];

	int type_size = 1;
	int length = 2;
	int receivetype, receivelength;
	int receiveId, receive_payload;

	sprintf(nonce1_string,"%ld", nonce1Val);

	// cmdline arguments should be 5
	 if (argc != 5) {
        usage(argv[0]);
    }
	else if (argc == 5){
		destination = argv[1];
		portN = atoi(argv[2]);
		user = argv[3];
		pwd = argv[4];

		// take the hash of password
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, pwd, strlen(pwd));
        SHA1_Final(hash1, &ctx);

        int i = 0;
		while (i < SHA_DIGEST_LENGTH) {
			sprintf( ((unsigned char*) &(Pw[i * 2])), "%02x", hash1[i] );
			i++;
		}
		
		printf("\n\n**********************************************************\n");
        printf("Client is Running to Server with following info:\n");
        printf("Destination: %s\n", destination);
	    printf("Port: %d\n", portN);
		printf("ID: %s\n", user);
	    printf("Password: %s\n", pwd);
		printf("Hashed Password: %s\n", Pw);
		printf("**********************************************************\n");

		strcpy(k, Pw);
		strcat(k, nonce1_string);
	}
	sock = clientTCPsock(destination, portN);
	if (sock < 0){
		errmesg("Cauldn't connect to Server");
		exit(1);
	}

	Buffer[0] = '\0';

	printf("\nSuccessfully connect to server\n");
	printf("\n\nType your command [ (｡◕‿‿◕｡) ]: ");

	while(fgets(Buffer, sizeof(Buffer), stdin)){
		if(strlen(Buffer) >= 2){
			printf("\n");
		    Buffer[strlen(Buffer) - 1] = '\0';
		    message = malloc(sizeof(struct Msg));
		    message->msgtype = 0x01;
		    message->paylen =  20;
		    memcpy(message->id,user,(15));
		    message->id[strlen(user)] = '\0';
		    message->payload = nonce1_string;

            printf("\n######################################################\n");
           	printf("Sending the following Message from Client to Server:\n");
			printf("MESSAGE TYPE:  0x0%d\n", message->msgtype);
            printf("PAYLEN:  %d\n", message->paylen);  
            printf("ID:  %s\n", message->id);
            printf("PAYLOAD:  %s\n", message->payload);
            printf("######################################################\n\n");

			write_msg_to_client(sock, message);
			
			receivedmsg = malloc(sizeof(struct Msg));
			receivetype = recv(sock, &receivedmsg->msgtype, type_size, 0);
    		receivelength = recv(sock, &receivedmsg->paylen, length, 0);
    		receiveId, receive_payload;
    		if (receivedmsg->paylen >= 16) {
        		receiveId = recv(sock, &receivedmsg->id, 16, 0);
    		}
    		if (receivedmsg->paylen > 16) {
        		receivedmsg->payload = (char*)malloc( (receivedmsg->paylen - 16) * sizeof(char));
        		receive_payload = recv(sock, receivedmsg->payload, (receivedmsg->paylen - 16), 0);
    		}

    		if (receivetype != type_size){
        		printf("ERROR: Invalid message type  received from server.\n");
        		free(receivedmsg);
        		receivedmsg = NULL;
    		}
    		if (receivelength != length){
        		printf("ERROR: Invalid message length received from server.\n");
        		free(receivedmsg);
        		receivedmsg = NULL;
    		}
    		if ( receiveId != 16 ){
            	printf("ERROR: Invalid message ID received from server.\n");
            	free(receivedmsg);
            	receivedmsg = NULL;
    		}
    		if ( receive_payload != (receivedmsg->paylen - 16) ){
        	    printf("ERROR: Invalid message payload received from server.\n");
            	free(receivedmsg);
            	receivedmsg =  NULL;
    		}
			printf("Received Message from Server:\n");
			server_msg = receivedmsg;
		
			printf("\n######################################################\n");
            printf("Client sends Message with these information to Server:\n");
            printf("MESSAGE TYPE:  0x0%d\n", server_msg->msgtype);
            printf("PAYLEN:  %d\n", server_msg->paylen);  
            printf("ID:  %s\n", server_msg->id);
            printf("PAYLOAD:  %s\n", server_msg->payload);
            printf("######################################################\n\n");

          	strcpy(nonce2_string, server_msg->payload);
           	nonce2_string[(message->paylen - 16) ] = '\0';
			strcat(k, nonce2_string);

   			SHA256_CTX sha256;
   			SHA256_Init(&sha256);
   			SHA256_Update(&sha256, k, strlen(k));
   			SHA256_Final(hash2, &sha256);
			
			int n = 0;
			while (n < SHA_DIGEST_LENGTH) {
				sprintf( ((unsigned char*) &(k[n* 2])), "%02x", hash2[n]);
				n++;
			}
            
			printf("Received nonce2(%s) from Server.\nWith key: %s\n\n", nonce2_string, k);
			
			nonce2Val = strtol(nonce2_string, &pointer, 10);
			nonce2Val = nonce2Val + 1;

			sprintf(nonce2_string,"%ld", nonce2Val);
			strcat(nonce2_string, Buffer);
			
			int ctxtlen;
			int sstringlen = strlen ((char *)nonce2_string);
			ctxtlen = aes_256_Encrypt(ctxt, nonce2_string, strlen ((char *)nonce2_string), k, iv);

			/*
			EVP_CIPHER_CTX *ctx;
          	ctx = EVP_CIPHER_CTX_new();
            int length;

            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, iv);
            EVP_EncryptUpdate(ctx, ctxt, &length, nonce2_string, strlen ((char *)nonce2_string));
            ctxtlen = length;
            EVP_EncryptFinal_ex(ctx, ctxt+length, &length);
            ctxtlen += length;
            EVP_CIPHER_CTX_free(ctx);
			*/
			if(server_msg->msgtype == 0x2){
                free(message);
                message = malloc(sizeof(struct Msg));
                message->msgtype = 0x03;
                message->paylen = 16 + ctxtlen + 1;
                memcpy(message->id,user,(15));
                message->id[strlen(user)] = '\0';

                ctxt[ctxtlen] = '\0';
                message->payload = ctxt;

                free(server_msg);

                printf("\n######################################################\n");
                printf("Sending the following Message from Client to Server:\n");
                printf("MESSAGE TYPE:  0x0%d\n", message->msgtype);
                printf("PAYLEN:  %d\n", message->paylen);
                printf("ID:  %s\n", message->id);
                printf("PAYLOAD:  %s\n", message->payload);
                printf("######################################################\n\n");

                write_msg_to_client(sock, message);
                
				receivedmsg = malloc(sizeof(struct Msg));
	            receivetype = recv(sock, &receivedmsg->msgtype, type_size, 0);
    	        receivelength = recv(sock, &receivedmsg->paylen, length, 0);
        	    receiveId, receive_payload;
            	if (receivedmsg->paylen >= 16) {
                	receiveId = recv(sock, &receivedmsg->id, 16, 0);
            	}
	            if (receivedmsg->paylen > 16) {
    	            receivedmsg->payload = (char*)malloc( (receivedmsg->paylen - 16) * sizeof(char));
        	        receive_payload = recv(sock, receivedmsg->payload, (receivedmsg->paylen - 16), 0);
            	}
	
	            if (receivetype != type_size){
    	            printf("ERROR: Invalid message type  received from server.\n");
        	        free(receivedmsg);
            	    receivedmsg = NULL;
            	}
            	if (receivelength != length){
                	printf("ERROR: Invalid message length received from server.\n");
	                free(receivedmsg);
	                receivedmsg = NULL;
	            }
	            if ( receiveId != 16 ){
    	            printf("ERROR: Invalid message ID received from server.\n");
    	            free(receivedmsg);
    	            receivedmsg = NULL;
    	        }
    	        if ( receive_payload != (receivedmsg->paylen - 16) ){
    	            printf("ERROR: Invalid message payload received from server.\n");
    	            free(receivedmsg);
    	            receivedmsg =  NULL;
    	        }
        	    printf("Received Message from Server:\n");
        	    server_msg = receivedmsg;

				int ptxtlen, len;
                ptxtlen = aes_256_Decrypt(ptxt, server_msg->payload, strlen(server_msg->payload), k, iv);
                /*
				ctx = EVP_CIPHER_CTX_new();

               	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, iv);
                EVP_DecryptUpdate(ctx, ptxt, &len, server_msg->payload, strlen(server_msg->payload));
                ptxtlen = len;

                EVP_DecryptFinal_ex(ctx, ptxt+len, &len);
                ptxtlen += len;
				*/

	           ptxt[ptxtlen] = '\0';
                nonce1Val2 = strtol(ptxt, &pointer, 10) - 1;
                                        
                if (server_msg-> msgtype == 0x4){
                    free(server_msg);
                    if(nonce1Val2 == nonce1Val){
                        printf("This response is valid!\n");
                    }
                    printf("Authentication Success!\n");
                    
					receivedmsg = malloc(sizeof(struct Msg));
	                receivetype = recv(sock, &receivedmsg->msgtype, type_size, 0);
    	            receivelength = recv(sock, &receivedmsg->paylen, length, 0);
        	        receiveId, receive_payload;
            	    if (receivedmsg->paylen >= 16) {
                	    receiveId = recv(sock, &receivedmsg->id, 16, 0);
                	}
                	if (receivedmsg->paylen > 16) {
                	    receivedmsg->payload = (char*)malloc( (receivedmsg->paylen - 16) * sizeof(char));
                	    receive_payload = recv(sock, receivedmsg->payload, (receivedmsg->paylen - 16), 0);
                	}       
                	    
                	if (receivetype != type_size){
                    	printf("ERROR: Invalid message type  received from server.\n");
                    	free(receivedmsg);
                    	receivedmsg = NULL;
                	}
                	if (receivelength != length){
                	    printf("ERROR: Invalid message length received from server.\n");
                    	free(receivedmsg);
                    	receivedmsg = NULL;
                	}               
                	if ( receiveId != 16 ){
                    	printf("ERROR: Invalid message ID received from server.\n");
                    	free(receivedmsg);
                    	receivedmsg = NULL;
                	}
                	if ( receive_payload != (receivedmsg->paylen - 16) ){
                    	printf("ERROR: Invalid message payload received from server.\n");
                    	free(receivedmsg);
                    	receivedmsg =  NULL;
                	}
                	printf("Received Message from Server:\n");
                	server_msg = receivedmsg;
				
					if(server_msg -> msgtype == 0x6){
                                
                        if(server_msg->payload != NULL){
                            strcpy(ctxt, server_msg->payload);
                                ptxtlen = aes_256_Decrypt(ptxt, ctxt, strlen(server_msg->payload), k, iv);
               					/*
								ctx = EVP_CIPHER_CTX_new();		
								int len;
               	 				EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, iv);
                				EVP_DecryptUpdate(ctx, ptxt, &len, ctxt, strlen(server_msg->payload));
                				ptxtlen = len;

                				EVP_DecryptFinal_ex(ctx, ptxt+len, &len);
                				ptxtlen += len;				 
								*/
				                ptxt[ptxtlen] = '\0';
                                printf("\nThe result of the command was:\n");
                                printf("%s\n", ptxt);
                        }
                        else{
                            printf("\nThe result of the command was:\ncommand not found\n\n");
                        }
                    }
                    else{
                        printf("ERROR: Received Invalid message.\n");
                    }
                }
                else if (server_msg-> msgtype == 0x5) { 
                        
                    free(server_msg);
                    printf("Authentication Failed!\n");
                    exit(1);
                }
                else {
                    printf("ERROR: Received Invalid message.\n");
                }
            }    
            else if (server_msg->msgtype == 0x6){
                
                if(server_msg->payload != NULL){
                    strcpy(ctxt , server_msg->payload);
					int ptxtlen, length;
                    ptxtlen = aes_256_Decrypt(ptxt, ctxt, strlen(server_msg->payload), k, iv);
                    /*
					ctx = EVP_CIPHER_CTX_new();

                	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, iv);
               	 	EVP_DecryptUpdate(ctx, ptxt, &length, server_msg->payload, strlen(server_msg->payload));
               	 	ptxtlen = length;

                	EVP_DecryptFinal_ex(ctx, ptxt+length, &length);
                	ptxtlen += length;
					*/
					ptxt[ptxtlen] = '\0';
                    printf("\nThe result of the command was:\n");
                    printf("%s\n", ptxt);   
                }
                else{
                    printf("\nThe result of the command was:\ncommand not found\n\n");
                }
            }
            else {
                printf("ERROR: Received Invalid message.\n");
            }
            
            Buffer[0] = '\0';
            printf("\n\nType your command [ (｡◕‿‿◕｡) ]: ");
            
        }
        else{
            exit(0);
        }
    }

    exit(0);
}
				
