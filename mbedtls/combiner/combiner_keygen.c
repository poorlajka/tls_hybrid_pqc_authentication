#include "combiner.h"
#include <stdlib.h>
#include <string.h>

struct options {
	size_t hybrid_len;
	combiner_t combiner;
	scheme_t* schemes;
} opt;

int main (int argc, char** argv) {
	
	for (int i = 1; i < argc; i++) {
		char* p = argv[i];
		char* q;
		if ((q = strchr(p, '=')) == NULL) {
            return 0;
        }
        *q++ = '\0';
		if (strcmp(p, "combiner") == 0) {
			if (strcmp(q, "CONCATENATION") == 0) {
				opt.combiner = CONCATENATION;
			}
			else if (strcmp(q, "STRONG_NESTING") == 0) {
				opt.combiner = STRONG_NESTING;
			}
		}
		else if (strcmp(p, "hybrid_len") == 0) {
			opt.hybrid_len = atoi(q);
			opt.schemes = malloc(sizeof(scheme_t) * opt.hybrid_len);
		}
		else if (strcmp(p, "schemes") == 0) {
            char * token = strtok(q, ",");
			for (size_t j = 0; j < opt.hybrid_len; ++j) {
				opt.schemes[j] = str_to_scheme_t(token);
                token = strtok(NULL, ",");
			}
		}
	}

    hybrid_t hybrid = {
        .len = opt.hybrid_len,
        .combiner = opt.combiner,
        .schemes = opt.schemes,
    };

    int ret = combiner_keygen(&hybrid);
    if (ret == -1) {
        printf("keygen failed \n");
        return 0;
    }
    ret = combiner_write_keyfile(&hybrid, "hybrid_keypair.key");
    if (ret == -1) {
        printf("keysave failed \n");
        return 0;
    }


    printf("keygen successfull\n");

    return 0;
}

