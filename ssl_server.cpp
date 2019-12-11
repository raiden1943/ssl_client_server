#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <pthread.h>
#include <list>
#define FAIL    -1

const int BUFSIZE = 1024;

using namespace std;

// Create the SSL socket and intialize the socket address structure

struct Info
{
	SSL *ssl;
	int num;
	Info()
	{
	}
	Info(SSL *ssl, int num)
	{
		this->ssl = ssl;
		this->num = num;
	}
};

struct Client
{
	pthread_t th;
	Info info;
	Client(pthread_t th, SSL *ssl, int num)
	{
		this->th = th;
		this->info.ssl = ssl;
		this->info.num = num;
	}
};

pthread_mutex_t mutex_lock;
bool broadcast_mode = false;
list<Client> clientList;

void* t_func(void *data)
{
	Info info = (*(Info *) data);
	SSL *ssl = info.ssl;
	int num = info.num;
    int sd;
    
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
    	while (1)
    	{
    		char buf[BUFSIZE];
    		
	        int received = SSL_read(ssl, buf, sizeof(buf)); /* get request */
	        if (received <= 0) 
	        {
	        	SSL_get_error(ssl, received);
	        	break;
			}
	        buf[received] = '\0';
	        printf("%s\n", buf);
	        
	        int sent = SSL_write(ssl, buf, strlen(buf)); /* send reply */
	        if (sent == 0)
	        {
        		SSL_get_error(ssl, received);
        		break;
			}
			if (broadcast_mode)
			{
				pthread_mutex_lock(&mutex_lock);
				for(auto it = clientList.begin(); it != clientList.end();)
				{
					if((*it).info.num == num)
					{
						it++;
						continue;
					}
					int sent = SSL_write((*it).info.ssl, buf, strlen(buf));
					if(sent <= 0)
					{
        				SSL_get_error(ssl, sent);
						pthread_cancel((*it).th);
						it = clientList.erase(it);
						printf("disconnected\n");
						break;
					}
					else
					{
						it++;
					}
				}
				pthread_mutex_unlock(&mutex_lock);
			}
		}
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
    
    pthread_mutex_lock(&mutex_lock);
    for(auto it = clientList.begin(); it != clientList.end();)
	{
		if((*it).info.num == num)
		{
			it = clientList.erase(it);
		}
		else
		{
			it++;
		}
	}
	pthread_mutex_unlock(&mutex_lock);
	printf("disconnected\n");
}

int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
	const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = DTLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;
	//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count == 3 && strcmp(Argc[2], "-b") == 0)
    {
    	broadcast_mode = true;
	}
    else if ( count != 2 )
    {
    	broadcast_mode = false;
        printf("syntax : ssl_server <port> [-b]\n");
        printf("sample : ssl_server 1234 -b\n");
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "test.com.crt", "test.com.key"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    
    int num = 1;
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        if (client < 0)
		{
			perror("ERROR on accept");
			break;
		}
		
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        
        pthread_t th;
        Info info(ssl, num);
		if(pthread_create(&th, NULL, t_func, (void *)&info) < 0)
	    {
	        perror("thread create error : ");
	        break;
	    }
		pthread_detach(th);
		
		pthread_mutex_lock(&mutex_lock);
		clientList.push_back(Client(th, ssl, num++));
		pthread_mutex_unlock(&mutex_lock);
    }
    
	pthread_mutex_lock(&mutex_lock);
	for(auto client : clientList)
	{
		int sd = SSL_get_fd(client.info.ssl);
	    SSL_free(client.info.ssl);
	    close(sd);
		pthread_cancel(client.th);
	}
	pthread_mutex_unlock(&mutex_lock);
    
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
