

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "dns.h"
#include "ssl.h"


#include <unistd.h>


#include "sti/sti.h"


char* strnstr(char* big, char* little, size_t len) {
	for(size_t i = 0; i < len && *big; i++, big++) {
		size_t j;
		for(j = 0; j + i < len; j++) {
			if(little[j] == 0) {
				return big; // match found
			}
			
			if(little[j] != big[j]) {
				goto NEXT; // to the outer loop;
			}
		}
		
		// len ran out; see if little ran out too
		if(little[j] == 0) return big; 
		
	NEXT:
	}
	
	return NULL; // no match found
}


void sen(sslconn* c, char* msg) {
	int len;
	char buf[1024];
	
	sleep(2);

	printf("> Sending \"%.*s\"\n", (int)strlen(msg) - 2, msg);
	
	ssl_write(c, msg, strlen(msg));
	
}



int get_code(char* s) {
	if(!(isdigit(s[0]) && isdigit(s[1]) && isdigit(s[2]))) {
		return -1;
	}
	
	return (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0');
}

int is_multiline(char* s) {
	return s[0] && s[1] && s[2] && (s[3] == '-');
}





typedef struct {
	sslconn* socket;
	char* buffer;
	ssize_t alloc, len;
	
	VEC(char*) recieved;
	
	char* sender;
	char* recipient;
	char* subject;
	char* body;

	
} smtp_state;

int get_response(smtp_state* st) {
	int len = 0;
	
	while(1) {
		len = ssl_read(st->socket, st->buffer + st->len, st->alloc - st->len);
		if(len <= 0) break;
	
		fwrite(st->buffer + st->len, 1, len, stdout);
		
		// try to nibble off some lines.
		char* end = strnstr(st->buffer + st->len, "\r\n", len);
		if(end == NULL) {
			continue;
		}
		
		int line_len = (end - st->buffer) + 2;
		char* line = strndup(st->buffer, line_len);		
		VEC_PUSH(&st->recieved, line);
		printf("Got line: '%s'\n", line);
		
		memmove(st->buffer, end + 2, st->len + len - line_len);
		st->len += len - line_len;
		
		if(!is_multiline(line)) break;
		
		usleep(100);
	}
	
	// hack
	if(!VEC_LEN(&st->recieved)) return 0;
	
	char* s = VEC_TAIL(&st->recieved);
	return get_code(s);
}





void init_send(smtp_state* st) {
	
	char** mx = mxlookup("mailinator.com.");
	if(!mx) {
		printf("MX lookup failed\n");
		exit(1);
	}
	
	for(char** c = mx; *c; c++) {
		printf("%s\n", *c);
	}
	
	ssl_connect(st->socket, mx[0], 25);
	// read 220
	while(1) {
		int len = ssl_read_raw(st->socket, st->buffer + st->len, st->alloc - st->len);
		if(len <= 0) break;
	     
		fwrite(st->buffer, 1, len, stdout);
		
		if(get_code(st->buffer) == 220) {
			st->len = 0;
			break;
		}
	}
	
	int len;
	char buf[1024];
	
	char* msg = "EHLO teraf.in\r\n";
	
	printf("> Sending EHLO\n");
	ssl_write_raw(st->socket, msg, strlen(msg));
	ssl_flush_raw(st->socket);
	while(1) {
	     len = ssl_read_raw(st->socket, st->buffer + st->len, st->alloc - st->len);
	     if(len <= 0) break;
	     
		fwrite(st->buffer, 1, len, stdout);
		if(get_code(st->buffer) == 250) {
			st->len = 0;
			break;
		}
	}
	
	ssl_starttls(st->socket);
	printf("> TLS complete\n");
	
	
	
	// BUG leaking mx
}


void send_mail(smtp_state* st) {
	int code;
	init_send(st);
	
	//code = get_response(st);
//	if(code == 250) {
		sen(st->socket, "MAIL FROM:<");
		sen(st->socket, st->sender);
		sen(st->socket, ">\r\n");
		ssl_flush(st->socket);
//	}
//	else {
//		printf("got code %d after starttls\n", code);
//		exit(1);
//	}
	
	code = get_response(st);
	if(code == 250) {
		sen(st->socket, "RCPT TO:<");
		sen(st->socket, st->recipient);
		sen(st->socket, ">\r\n");
		ssl_flush(st->socket);
	}
	else {
		printf("got code %d after mail from\n", code);
		exit(1);
	}
	
	code = get_response(st);
	if(code == 250) {
		sen(st->socket, "DATA \r\n");
		ssl_flush(st->socket);
	}
	else {
		printf("got code %d after rctp to\n", code);
		exit(1);
	}

	code = get_response(st);
	if(code == 354) {
		sen(st->socket, "Subject:");
		sen(st->socket, st->subject);
		sen(st->socket, "\r\n");
		sen(st->socket, st->body);
		sen(st->socket, "\r\n.\r\n");
		ssl_flush(st->socket);
	}
	else {
		printf("got code %d after data\n", code);
		exit(1);
	}
	
	code = get_response(st);
	if(code == 250) {
		sen(st->socket, "QUIT\r\n");
		ssl_flush(st->socket);
	}
	else {
		printf("got code %d after data\n", code);
		exit(1);
	}

	
	code = get_response(st);
	if(code == 221) {
//		sen(st->socket, "QUIT \r\n");
		printf("> Success\n");
	}
	else {
		printf("got code %d after quit\n", code);
		exit(1);
	}

	
	
	
	
}


int main(int argc, char* argv[]) {

	
	sslconn socket = {0};
	
	smtp_state st = {0};
	st.socket = &socket;
	st.alloc = 1024;
	st.len = 0;
	st.buffer = malloc(sizeof(*st.buffer) * st.alloc);
	
	st.sender = "limpiavidrios@mailinator.com";
	st.recipient = "limpiavidrios@mailinator.com";
	st.subject = "Test Message";
	st.body = "test.";
	
	send_mail(&st);
	
	ssl_close(&socket);


	return 0;
}








