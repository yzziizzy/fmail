#ifndef __fmail__ssl_h__
#define __fmail__ssl_h__


#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>





typedef struct {
	BIO* ssl_bio;
	BIO* raw_bio;
	
	SSL_CTX *ctx;
	SSL *ssl;
} sslconn;


void ssl_connect(sslconn* c, char* address, int port);
void ssl_starttls(sslconn* c);

void ssl_write(sslconn* c, unsigned char* s, int slen);
int ssl_read(sslconn* c, unsigned char* buf, int maxlen);
void ssl_write_raw(sslconn* c, unsigned char* s, int slen);
int ssl_read_raw(sslconn* c, unsigned char* buf, int maxlen);

void ssl_flush(sslconn* c);
void ssl_flush_raw(sslconn* c);

void ssl_close(sslconn* c);





#endif __fmail__ssl_h__
