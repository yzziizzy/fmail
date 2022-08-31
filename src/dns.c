
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>





char** mxlookup(char* domain) {
	
	struct __res_state st;
	unsigned char answer[1024];
	
	res_ninit(&st);
	
	int len = res_nquery(&st, domain, C_IN, T_MX, answer, 1024);
	if(len < 0) {
		printf("mx resolve failure for %s\n", domain);
		return NULL;
	}
	

	
	// The "ns_" functions below are completely undocumented as of August 2022.
	// Seriously, most of the glibc source code doesn't even have comments.
	//
	// To whoever decided that us plebs are unfit to use them but didn't document an alternative:
	//
	//     Fuck. You.
	//
	
	ns_msg msg = {0};
	
	if(ns_initparse(answer, len, &msg)) {
		printf("ns_initparse failure for %s\n", domain);
		return NULL;
	}
	
	int msg_c = ns_msg_count(msg, ns_s_an);
	
	int on = 0;
	char** out = calloc(1, sizeof(*out) * (msg_c + 1));
	
	for(int i = 0; i < msg_c; i++) {
		ns_rr rr;
		
		if(ns_parserr(&msg, ns_s_an, i, &rr)) {
			printf("ns_parserr error for %s\n", domain);
			continue;
		}
		
		switch(ns_rr_type(rr)) {
			case ns_t_mx: {
				char buf[1024];
				int dl = ns_rr_rdlen(rr); 
				unsigned char* data = (unsigned char*)ns_rr_rdata(rr);
				
				int bl = ns_sprintrr(&msg, &rr, NULL, NULL,  buf, 1024);
	            
	
				if(ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_mx) {
					char mx_name[1024];
					
		            dn_expand(ns_msg_base(msg), ns_msg_base(msg) + ns_msg_size(msg), ns_rr_rdata(rr) + NS_INT16SZ, mx_name, 1024);
					out[on++] = strdup(mx_name);
				}
				
			}
				
		}
	}
	
	
	res_nclose(&st);
	
	return out;
}



