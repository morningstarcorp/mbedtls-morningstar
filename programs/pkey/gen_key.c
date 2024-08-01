/*
 *  Key generation application
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
Custom edits by csmith

The program was edited to instead generate a password protected private key. This
only works right now for output formats of DER. I also decreased the default bit
size for RSA to 2048 as that's likely what we'll use.

See comments in write_private_key for details.
*/

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_PK_WRITE_C) || !defined(MBEDTLS_PEM_WRITE_C) ||    \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) ||           \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_BIGNUM_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_PK_WRITE_C and/or MBEDTLS_FS_IO and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
                   "MBEDTLS_PEM_WRITE_C and/or MBEDTLS_BIGNUM_C "
                   "not defined.\n");
    mbedtls_exit(0);
}
#else

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/pkcs5.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>

#define DEV_RANDOM_THRESHOLD        32

int dev_random_entropy_poll(void *data, unsigned char *output,
                            size_t len, size_t *olen)
{
    FILE *file;
    size_t ret, left = len;
    unsigned char *p = output;
    ((void) data);

    *olen = 0;

    file = fopen("/dev/random", "rb");
    if (file == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    while (left > 0) {
        /* /dev/random can return much less than requested. If so, try again */
        ret = fread(p, 1, left, file);
        if (ret == 0 && ferror(file)) {
            fclose(file);
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }

        p += ret;
        left -= ret;
        sleep(1);
    }
    fclose(file);
    *olen = len;

    return 0;
}
#endif /* !_WIN32 */

#if defined(MBEDTLS_ECP_C)
#define DFL_EC_CURVE            mbedtls_ecp_curve_list()->grp_id
#else
#define DFL_EC_CURVE            0
#endif

#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
#define USAGE_DEV_RANDOM \
    "    use_dev_random=0|1    default: 0\n"
#else
#define USAGE_DEV_RANDOM ""
#endif /* !_WIN32 && MBEDTLS_FS_IO */

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE         2048
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_DER
#define DFL_USE_DEV_RANDOM      0

#define USAGE \
    "\n usage: gen_key param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    type=rsa|ec           default: rsa\n"          \
    "    rsa_keysize=%%d        default: 4096\n"        \
    "    ec_curve=%%s           see below\n"            \
    "    filename=%%s           default: keyfile.key\n" \
    "    format=pem|der        default: pem\n"          \
    USAGE_DEV_RANDOM                                    \
    "\n"


/*
 * global options
 */
struct options {
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
    int use_dev_random;         /* use /dev/random as entropy source    */
} opt;

static int write_private_key(mbedtls_pk_context *key, const char *output_file)
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
	unsigned char encrypted_buffer[4096];
	size_t encrypted_len;
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if (opt.format == FORMAT_PEM) {
        if ((ret = mbedtls_pk_write_key_pem(key, output_buf, 16000)) != 0) {
            return ret;
        }

        len = strlen((char *) output_buf);
    } else {
        if ((ret = mbedtls_pk_write_key_der(key, output_buf, 16000)) < 0) {
            return ret;
        }

        len = ret;
        c = output_buf + sizeof(output_buf) - len;

		/*
		Convert to PKCS#8 format

		Password protected keys are stored in Encrypted for PKCS#8, which expects
		the encrypted data to itself be an unecrypted PKCS#8 formatted key.

		PKCS#8 essentially adds extra metadata onto the existing private key format
		(in this case PKCS#1 RSA key)

		See RFC 5208 section 5 for more details

		Note for all ASN.1 writes below that mbedtls works backwords when building
		ASN.1 structures.
		*/
		// privateKey field
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, output_buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, output_buf,
			(MBEDTLS_ASN1_OCTET_STRING | MBEDTLS_ASN1_PRIMITIVE)));

		// privateKeyAlgorithm field
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, output_buf,
			MBEDTLS_OID_PKCS1_RSA, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_RSA), 0));

		// version field
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, output_buf, 0));

		// Wrap PrivateKeyInfo in SEQUENCE tag
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, output_buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, output_buf,
			(MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)));

		// Write unecrypted key for debug purposes
		if ((f = fopen("keyfile_2.key", "wb")) == NULL) {
			return -1;
		}

		if (fwrite(c, 1, len, f) != len) {
			fclose(f);
			return -1;
		}

		fclose(f);

		{
			/*
			Generate password protected key

			In order to do this we must first setup a valid PKCS#5 PBES2 structure
			(see RFC 8018 section A.4). This provides mbedtls with the information
			it needs to encrypt the unencrypted PKCS#8 key.

			Then, we put the encrypted data into a valid PKCS#8 encrypted structure
			(see RFC 5208 section 6).
			*/
			const char password[] = "morningstar";
			const unsigned char salt[8] = { 0x35, 0x99, 0x62, 0x6B, 0x93, 0x1A, 0xDA, 0xE3 };
			const unsigned char iv[16] = { 0x03, 0xAA, 0xD8, 0xA2, 0x51, 0xDC, 0xE3, 0x75, 0x34, 0x5A, 0xF7, 0x39, 0x26, 0x19, 0x0F, 0x17 };
			mbedtls_asn1_buf pbe_params;
			unsigned char pbuf[74];
			unsigned char *p = pbuf + sizeof(pbuf);
			int sequence_len, total_len;

			total_len = sequence_len = 0;

			// === encryptionScheme ===
			// AES-256-CBC AlgorithmIdentifier includes a single parameter: the IV
			// (See X.509 standard)

			// AES-InitializationVector
			MBEDTLS_ASN1_CHK_ADD(sequence_len, mbedtls_asn1_write_octet_string(&p, pbuf,
				iv, sizeof(iv)));

			// ID
			sequence_len = mbedtls_asn1_write_algorithm_identifier(&p,
				pbuf, MBEDTLS_OID_AES_256_CBC,
				MBEDTLS_OID_SIZE(MBEDTLS_OID_AES_256_CBC), sequence_len);

			total_len += sequence_len;
			sequence_len = 0;

			// === keyDerivationFunc ===
			// keyDerivationFunc is an AlgorithmIdentifier of type PBKDF2 (RFC 8018 A.2)

			// prf (digest algorithm for generating the AES key)
			MBEDTLS_ASN1_CHK_ADD(sequence_len, mbedtls_asn1_write_algorithm_identifier(&p,
				pbuf, MBEDTLS_OID_HMAC_SHA256,
				MBEDTLS_OID_SIZE(MBEDTLS_OID_HMAC_SHA256), 0));

			// keyLength is ignored

			// iterationCount
			MBEDTLS_ASN1_CHK_ADD(sequence_len, mbedtls_asn1_write_int(&p, pbuf, 2048));

			// salt-specified
			MBEDTLS_ASN1_CHK_ADD(sequence_len, mbedtls_asn1_write_octet_string(&p, pbuf,
				salt, sizeof(salt)));

			// Add wrapping SEQUENCE Tag
			MBEDTLS_ASN1_CHK_ADD(sequence_len, mbedtls_asn1_write_len(&p, pbuf, sequence_len));
			MBEDTLS_ASN1_CHK_ADD(sequence_len, mbedtls_asn1_write_tag(&p, pbuf,
				MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED));

			// keyDerivationFunc AlgorithmIdentifier-ID
			sequence_len = mbedtls_asn1_write_algorithm_identifier(&p,
				pbuf, MBEDTLS_OID_PKCS5_PBKDF2,
				MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBKDF2), sequence_len);

			total_len += sequence_len;
			pbe_params.p = p;
			pbe_params.len = total_len;
			pbe_params.tag = (MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

			// Encrypt the key
			ret = mbedtls_pkcs5_pbes2_ext(&pbe_params, MBEDTLS_PKCS5_ENCRYPT,
				(unsigned char*)password, strlen(password), c, len, encrypted_buffer,
				sizeof(encrypted_buffer), &encrypted_len);

			if (ret != 0) {
				return ret;
			}

			/*
			Wrap the encrypted key in a valid PKCS#8 Encrypted Key format
			*/

			p = output_buf + sizeof(output_buf);

			// encryptedData
			mbedtls_asn1_write_octet_string(&p, output_buf, encrypted_buffer,
				encrypted_len);

			// encryptedAlgorithm params
			p -= pbe_params.len;
			memcpy(p, pbe_params.p, pbe_params.len);

			total_len = pbe_params.len;
			MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_len(&p, output_buf, pbe_params.len));
			MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_tag(&p, output_buf, (MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)));

			// encryptedAlgorithm ID
			mbedtls_asn1_write_algorithm_identifier(&p, output_buf,
				MBEDTLS_OID_PKCS5_PBES2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBES2),
				total_len);

			total_len = (output_buf + sizeof(output_buf)) - p;

			// Sequence header for PKCS#8
			MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_len(&p, output_buf, total_len));
			MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_tag(&p, output_buf, (MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)));

			c = p;
			len = ((output_buf + sizeof(output_buf)) - p);
		}
    }

    if ((f = fopen(output_file, "wb")) == NULL) {
        return -1;
    }

    if (fwrite(c, 1, len, f) != len) {
        fclose(f);
        return -1;
    }

    fclose(f);

    return 0;
}

#if defined(MBEDTLS_ECP_C)
static int show_ecp_key(const mbedtls_ecp_keypair *ecp, int has_private)
{
    int ret = 0;

    const mbedtls_ecp_curve_info *curve_info =
        mbedtls_ecp_curve_info_from_grp_id(
            mbedtls_ecp_keypair_get_group_id(ecp));
    mbedtls_printf("curve: %s\n", curve_info->name);

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi D;
    mbedtls_mpi_init(&D);
    mbedtls_ecp_point pt;
    mbedtls_ecp_point_init(&pt);
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    MBEDTLS_MPI_CHK(mbedtls_ecp_export(ecp, &grp,
                                       (has_private ? &D : NULL),
                                       &pt));

    unsigned char point_bin[MBEDTLS_ECP_MAX_PT_LEN];
    size_t len = 0;
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(
                        &grp, &pt, MBEDTLS_ECP_PF_UNCOMPRESSED,
                        &len, point_bin, sizeof(point_bin)));
    switch (mbedtls_ecp_get_type(&grp)) {
        case MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS:
            if ((len & 1) == 0 || point_bin[0] != 0x04) {
                /* Point in an unxepected format. This shouldn't happen. */
                ret = -1;
                goto cleanup;
            }
            MBEDTLS_MPI_CHK(
                mbedtls_mpi_read_binary(&X, point_bin + 1, len / 2));
            MBEDTLS_MPI_CHK(
                mbedtls_mpi_read_binary(&Y, point_bin + 1 + len / 2, len / 2));
            mbedtls_mpi_write_file("X_Q:   ", &X, 16, NULL);
            mbedtls_mpi_write_file("Y_Q:   ", &Y, 16, NULL);
            break;
        case MBEDTLS_ECP_TYPE_MONTGOMERY:
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, point_bin, len));
            mbedtls_mpi_write_file("X_Q:   ", &X, 16, NULL);
            break;
        default:
            mbedtls_printf(
                "This program does not yet support listing coordinates for this curve type.\n");
            break;
    }

    if (has_private) {
        mbedtls_mpi_write_file("D:     ", &D, 16, NULL);
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&D);
    mbedtls_ecp_point_free(&pt);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    return ret;
}
#endif

int main(int argc, char *argv[])
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context key;
    char buf[1024];
    int i;
    char *p, *q;
#if defined(MBEDTLS_RSA_C)
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
#endif /* MBEDTLS_RSA_C */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";
#if defined(MBEDTLS_ECP_C)
    const mbedtls_ecp_curve_info *curve_info;
#endif

    /*
     * Set to sane values
     */
#if defined(MBEDTLS_RSA_C)
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);
#endif /* MBEDTLS_RSA_C */

    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(buf, 0, sizeof(buf));

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (argc < 1) {
usage:
        mbedtls_printf(USAGE);
#if defined(MBEDTLS_ECP_C)
        mbedtls_printf(" available ec_curve values:\n");
        curve_info = mbedtls_ecp_curve_list();
        mbedtls_printf("    %s (default)\n", curve_info->name);
        while ((++curve_info)->name != NULL) {
            mbedtls_printf("    %s\n", curve_info->name);
        }
#endif /* MBEDTLS_ECP_C */
        goto exit;
    }

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.ec_curve            = DFL_EC_CURVE;
    opt.filename            = DFL_FILENAME;
    opt.format              = DFL_FORMAT;
    opt.use_dev_random      = DFL_USE_DEV_RANDOM;

    for (i = 1; i < argc; i++) {
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL) {
            goto usage;
        }
        *q++ = '\0';

        if (strcmp(p, "type") == 0) {
            if (strcmp(q, "rsa") == 0) {
                opt.type = MBEDTLS_PK_RSA;
            } else if (strcmp(q, "ec") == 0) {
                opt.type = MBEDTLS_PK_ECKEY;
            } else {
                goto usage;
            }
        } else if (strcmp(p, "format") == 0) {
            if (strcmp(q, "pem") == 0) {
                opt.format = FORMAT_PEM;
            } else if (strcmp(q, "der") == 0) {
                opt.format = FORMAT_DER;
            } else {
                goto usage;
            }
        } else if (strcmp(p, "rsa_keysize") == 0) {
            opt.rsa_keysize = atoi(q);
            if (opt.rsa_keysize < 1024 ||
                opt.rsa_keysize > MBEDTLS_MPI_MAX_BITS) {
                goto usage;
            }
        }
#if defined(MBEDTLS_ECP_C)
        else if (strcmp(p, "ec_curve") == 0) {
            if ((curve_info = mbedtls_ecp_curve_info_from_name(q)) == NULL) {
                goto usage;
            }
            opt.ec_curve = curve_info->grp_id;
        }
#endif
        else if (strcmp(p, "filename") == 0) {
            opt.filename = q;
        } else if (strcmp(p, "use_dev_random") == 0) {
            opt.use_dev_random = atoi(q);
            if (opt.use_dev_random < 0 || opt.use_dev_random > 1) {
                goto usage;
            }
        } else {
            goto usage;
        }
    }

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
    if (opt.use_dev_random) {
        if ((ret = mbedtls_entropy_add_source(&entropy, dev_random_entropy_poll,
                                              NULL, DEV_RANDOM_THRESHOLD,
                                              MBEDTLS_ENTROPY_SOURCE_STRONG)) != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_entropy_add_source returned -0x%04x\n",
                           (unsigned int) -ret);
            goto exit;
        }

        mbedtls_printf("\n    Using /dev/random, so can take a long time! ");
        fflush(stdout);
    }
#endif /* !_WIN32 && MBEDTLS_FS_IO */

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                       (unsigned int) -ret);
        goto exit;
    }

    /*
     * 1.1. Generate the key
     */
    mbedtls_printf("\n  . Generating the private key ...");
    fflush(stdout);

    if ((ret = mbedtls_pk_setup(&key,
                                mbedtls_pk_info_from_type((mbedtls_pk_type_t) opt.type))) != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret);
        goto exit;
    }

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if (opt.type == MBEDTLS_PK_RSA) {
// Uncomment to instead load an existing key
#if 0
		unsigned char buffer[2048];
		FILE *f;

		mbedtls_pk_free(&key);
		mbedtls_pk_init(&key);

		if ((f = fopen("private_2048.key", "rb")) == NULL) {
			mbedtls_printf(" failed\n ! Could not open private_2048.key");
			goto exit;
		}

		fseek(f, 0, SEEK_END);
		size_t fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize > sizeof(buffer)) {
			mbedtls_printf(" failed\n ! File size of %llu too large!", fsize);
			goto exit;
		}

		fread(buffer, fsize, 1, f);

		fclose(f);

		ret = mbedtls_pk_parse_key(&key, buffer, fsize, NULL, 0,
			mbedtls_ctr_drbg_random, &ctr_drbg);

        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned -0x%04x",
                           (unsigned int) -ret);
            goto exit;
        }
#else
        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                                  opt.rsa_keysize, 65537);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_rsa_gen_key returned -0x%04x",
                           (unsigned int) -ret);
            goto exit;
        }
#endif
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if (opt.type == MBEDTLS_PK_ECKEY) {
        ret = mbedtls_ecp_gen_key((mbedtls_ecp_group_id) opt.ec_curve,
                                  mbedtls_pk_ec(key),
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_ecp_gen_key returned -0x%04x",
                           (unsigned int) -ret);
            goto exit;
        }
    } else
#endif /* MBEDTLS_ECP_C */
    {
        mbedtls_printf(" failed\n  !  key type not supported\n");
        goto exit;
    }

    /*
     * 1.2 Print the key
     */
    mbedtls_printf(" ok\n  . Key information:\n");

#if defined(MBEDTLS_RSA_C)
    if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA) {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

        if ((ret = mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E)) != 0 ||
            (ret = mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP))      != 0) {
            mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
            goto exit;
        }

        mbedtls_mpi_write_file("N:  ",  &N,  16, NULL);
        mbedtls_mpi_write_file("E:  ",  &E,  16, NULL);
        mbedtls_mpi_write_file("D:  ",  &D,  16, NULL);
        mbedtls_mpi_write_file("P:  ",  &P,  16, NULL);
        mbedtls_mpi_write_file("Q:  ",  &Q,  16, NULL);
        mbedtls_mpi_write_file("DP: ",  &DP, 16, NULL);
        mbedtls_mpi_write_file("DQ:  ", &DQ, 16, NULL);
        mbedtls_mpi_write_file("QP:  ", &QP, 16, NULL);
    } else
#endif
#if defined(MBEDTLS_ECP_C)
    if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY) {
        if (show_ecp_key(mbedtls_pk_ec(key), 1) != 0) {
            mbedtls_printf(" failed\n  ! could not export ECC parameters\n\n");
            goto exit;
        }
    } else
#endif
    mbedtls_printf("  ! key type not supported\n");

    /*
     * 1.3 Export key
     */
    mbedtls_printf("  . Writing key to file...");

    if ((ret = write_private_key(&key, opt.filename)) != 0) {
        mbedtls_printf(" failed\n");
        goto exit;
    }

    mbedtls_printf(" ok\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
#ifdef MBEDTLS_ERROR_C
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" - %s\n", buf);
#else
        mbedtls_printf("\n");
#endif
    }

#if defined(MBEDTLS_RSA_C)
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
#endif /* MBEDTLS_RSA_C */

    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    mbedtls_exit(exit_code);
}
#endif /* program viability conditions */
