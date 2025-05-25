#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "combiner.h"

struct options {
	size_t hybrid_len;
	combiner_t combiner;
	scheme_t* schemes;
} opt;

int main (int argc, char** argv) {
    char outfile[100];
	
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
            else {
                printf("Invalid combiner type\n");
                return -1;
            }
		}
		else if (strcmp(p, "hybrid_len") == 0) {
			opt.hybrid_len = atoi(q);
			opt.schemes = malloc(sizeof(scheme_t) * opt.hybrid_len);
		}
		else if (strcmp(p, "outfile") == 0) {
            strncpy(outfile, q, sizeof(outfile));
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

    unsigned char text[255];
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 255; i++) {
        text[i] = rand() % 256;
    }
    msg_t message = {
        .content = (unsigned char*)text,
        .len = sizeof(text)
    };
    
    ret = combiner_sign(&hybrid, message);
    if (ret == -1) {
        printf("Signing failed \n");
        return 0;
    }

    size_t sig_len = 0;
    if (hybrid.combiner == CONCATENATION) {
        for (size_t i = 0; i < hybrid.len; ++i) {
            sig_len += hybrid.signature.concat.lens[i];
        }
    }
    else if (hybrid.combiner == STRONG_NESTING) {
        sig_len += hybrid.signature.nesting.len;
    }

    int key_size = hybrid.keypair.public_key_len + sig_len;

    FILE* fstream;
    if ((fstream = fopen(outfile, "wb")) == NULL) {
        return -1;
    }

    if (fprintf(fstream, "%d\n", key_size) < 0) {
        fclose(fstream);
        return -1;
    }
    printf("total size: %d\n", key_size);

    fclose(fstream);

}



