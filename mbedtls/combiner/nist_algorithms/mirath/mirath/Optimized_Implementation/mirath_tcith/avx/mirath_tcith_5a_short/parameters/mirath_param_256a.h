#ifndef MIRATH_TCITH_MIRATH_PARAM_256A_H
#define MIRATH_TCITH_MIRATH_PARAM_256A_H


#define MIRATH_SECURITY 256			        /**< Expected security level (bits) */
#define MIRATH_SECURITY_BYTES 32		    /**< Expected security level (bytes) */

#define MIRATH_PARAM_SALT_BYTES (2 * MIRATH_SECURITY_BYTES)

#define MIRATH_SECRET_KEY_BYTES 64		    /**< Secret key size */
#define MIRATH_PUBLIC_KEY_BYTES 147		    /**< Public key size */
#define MIRATH_SIGNATURE_BYTES 12413		/**< Signature size */

#define MIRATH_PARAM_Q 16			        /**< Parameter q of the scheme (finite field GF(q^m)) */
#define MIRATH_PARAM_M 22			        /**< Parameter m of the scheme (finite field GF(q^m)) */
#define MIRATH_PARAM_K 255			        /**< Parameter k of the scheme (code dimension) */
#define MIRATH_PARAM_N 22			        /**< Parameter n of the scheme (code length) */
#define MIRATH_PARAM_R 6			        /**< Parameter r of the scheme (rank of vectors) */

#define MIRATH_PARAM_N_1 4096			    /**< Parameter N_1 of the scheme */
#define MIRATH_PARAM_N_2 4096			    /**< Parameter N_2 of the scheme */
#define MIRATH_PARAM_N_1_BITS 12		    /**< Parameter tau_1 of the scheme (bits) */
#define MIRATH_PARAM_N_2_BITS 12		    /**< Parameter tau_2 of the scheme (bits) */
#define MIRATH_PARAM_N_1_BYTES 2		    /**< Parameter tau_1 of the scheme (bytes) */
#define MIRATH_PARAM_N_2_BYTES 2		    /**< Parameter tau_2 of the scheme (bytes) */
#define MIRATH_PARAM_N_1_MASK 0xf		    /**< Parameter tau_1 of the scheme (mask) */
#define MIRATH_PARAM_N_2_MASK 0xf		    /**< Parameter tau_2 of the scheme (mask) */
#define MIRATH_PARAM_TAU 23			        /**< Parameter tau of the scheme (number of iterations) */
#define MIRATH_PARAM_TAU_1 23			    /**< Parameter tau_1 of the scheme (number of iterations concerning N1) */
#define MIRATH_PARAM_TAU_2 0		        /**< Parameter tau_2 of the scheme (number of iterations concerning N2) */
#define MIRATH_PARAM_RHO 22			        /**< Parameter rho of the scheme (dimension of the extension)*/
#define MIRATH_PARAM_MU 3			        /**< Parameter mu of the scheme */

#define MIRATH_PARAM_TREE_LEAVES 94208	    /**< Number of leaves in the tree */

#define MIRATH_PARAM_CHALLENGE_2_BYTES 35	/**< Number of bytes required to store the second challenge */
#define MIRATH_PARAM_HASH_2_MASK_BYTES 1	/**< Number of last bytes in the second hash to be zero */
#define MIRATH_PARAM_HASH_2_MASK 0x07	    /**< Mask for the last byte in the second hash to be zero */
#define MIRATH_PARAM_T_OPEN 232		        /**< Maximum sibling path length allowed */


#endif //MIRATH_TCITH_MIRATH_PARAM_256A_H
