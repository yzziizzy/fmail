
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ssl.h"






void ssl_global_init(void) {
	SSL_library_init();

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	
	OpenSSL_add_all_algorithms();

    
  /* Include <openssl/opensslconf.h> to get this define */
#if defined (OPENSSL_THREADS)
  fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}


void ssl_connect(sslconn* c, char* address, int port) {
	char port_s[32];
	snprintf(port_s, 32, "%d", port);
	
	

	
	
	c->raw_bio = BIO_new_connect(address);
//	BIO_set_nbio(c->raw_bio, 1);

	
//	BIO_set_conn_hostname(c->raw_bio, address);
	BIO_set_conn_port(c->raw_bio, port_s);
	
	if(BIO_do_connect(c->raw_bio) <= 0) {
	     fprintf(stderr, "Error connecting to %s\n", address);
	     ERR_print_errors_fp(stderr);
	     exit(1);
	}
	else {
		printf("connected\n");
	}
}


void ssl_starttls(sslconn* c) {


	c->ctx = SSL_CTX_new(TLS_client_method());
	/*
	if (!SSL_CTX_use_certificate_file(c->ctx, "server.pem", SSL_FILETYPE_PEM)
		|| !SSL_CTX_use_PrivateKey_file(c->ctx, "server.pem", SSL_FILETYPE_PEM)
		|| !SSL_CTX_check_private_key(c->ctx)) {
	     
		fprintf(stderr, "Error setting up SSL_CTX\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	*/
	 /* XXX Other things like set verify locations, EDH temp callbacks. */
	
	/* New SSL BIO setup as server */
	c->ssl_bio = BIO_new_ssl(c->ctx, 0);
	BIO_get_ssl(c->ssl_bio, &c->ssl);
	if (c->ssl == NULL) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	SSL_set_mode(c->ssl, SSL_MODE_AUTO_RETRY);
	c->ssl_bio = BIO_push(c->raw_bio, c->ssl_bio);

	
	
	if(BIO_do_handshake(c->ssl_bio) <= 0) {
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	
	if(SSL_get_verify_result(c->ssl) != X509_V_OK) {
		fprintf(stderr, "SSL verification failed\n");
	}
	
	printf(">> SSL handshake complete\n");
}


void ssl_flush(sslconn* c) {
	BIO_flush(c->ssl_bio);
}
void ssl_flush_raw(sslconn* c) {
	BIO_flush(c->raw_bio);
}

void ssl_write(sslconn* c, unsigned char* s, int slen) {
	BIO_write(c->ssl_bio, s, slen);
}


int ssl_read(sslconn* c, unsigned char* buf, int maxlen) {
	return BIO_read(c->ssl_bio, buf, maxlen);
}

void ssl_write_raw(sslconn* c, unsigned char* s, int slen) {
	BIO_write(c->raw_bio, s, slen);
}


int ssl_read_raw(sslconn* c, unsigned char* buf, int maxlen) {
	return BIO_read(c->raw_bio, buf, maxlen);
}


void ssl_close(sslconn* c) {
	BIO_flush(c->ssl_bio);
	BIO_free_all(c->ssl_bio);
}







