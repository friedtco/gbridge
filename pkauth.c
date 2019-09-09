/*
 * Copyright (c) 2019 Christopher Friedt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "debug.h"
#include "gbridge.h"
#include "greybus.h"
#include "greybus_protocols.h"
#include "pkauth.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#define PKAUTH_AES_BLOCK_SIZE 16

typedef const EVP_CIPHER *(*cbc_inst_func)(void);
struct supported_cbc_inst {
	int keysize;
	cbc_inst_func cbc_inst;
};

static uint16_t pkauth_operation_id;
static char *pkauth_authorized_keys;
static RSA *pkauth_id_rsa;
static unsigned pkauth_timeout_ms;


static const struct supported_cbc_inst pkauth_cbc_inst[] = {
	{ 16, EVP_aes_128_cbc },
	{ 24, EVP_aes_192_cbc },
	{ 32, EVP_aes_256_cbc },
};

static cbc_inst_func pkauth_cbc_inst_by_size( size_t size ) {
	for( size_t i = 0; i < ARRAY_SIZE(pkauth_cbc_inst); i++ ) {
		if ( pkauth_cbc_inst[ i ].keysize == size ) {
			return pkauth_cbc_inst[ i ].cbc_inst;
		}
	}
	return NULL;
}

static int pkauth_buffer_file(const char *path, char **buffer, size_t *len) {

	int r;
	int fd;
	off_t off;
	ssize_t n;

	if (NULL == path || NULL == buffer) {
		pr_err("one or more arguments are NULL\n");
		r = -EINVAL;
		goto out;
	}

	r = open(path, O_RDONLY);
	if (-1 == r) {
		pr_err("failed to open %s: %s\n", path, strerror(errno));
		r = -errno;
		goto out;
	}
	fd = r;

	off = lseek(fd, 0, SEEK_END);
	if (-1 == off) {
		pr_err("failed to lseek %s: %s\n", path, strerror(errno));
		r = -errno;
		goto closefd;
	}
	*len = off;
	off = lseek(fd, 0, SEEK_SET);
	if (-1 == off || 0 != off) {
		pr_err("failed to lseek %s: %s\n", path, strerror(errno));
		r = -errno;
		goto closefd;
	}

	// this will be encoded as a string, so add a null terminator ('\0')
	*buffer = malloc( *len + 1 );
	if (NULL == *buffer) {
		pr_err("failed to buffer %s\n", path);
		r = -ENOMEM;
		goto closefd;
	}

	n = read(fd, *buffer, *len);
	if (-1 == n || n != *len) {
		pr_err("failed to read %s: %s\n", path, strerror(errno));
		r = -errno;
		goto freebuffer;
	}
	(*buffer)[*len] = '\0';

	r = 0; // success \o/
	goto closefd;

freebuffer:
	free(*buffer);
	*buffer = NULL;

closefd:
	close(fd);

out:
	return r;
}

void pkauth_set_timeout_ms(unsigned timeout) {
	pkauth_timeout_ms = timeout;
}

int pkauth_init_from(const char *id_rsa_file, const char *authorized_keys_file) {

	int r;
	char *id_rsa;
	char *authorized_keys;
	size_t id_rsa_len;
	size_t authorized_keys_len;

	r = pkauth_buffer_file(id_rsa_file, &id_rsa, &id_rsa_len);
	if (r) {
		goto out;
	}

	r = pkauth_buffer_file(authorized_keys_file, &authorized_keys, &authorized_keys_len);
	if (r) {
		goto freersa;
	}

	r = pkauth_init(id_rsa, authorized_keys);
	if (r) {
		goto freeauthkeys;
	}

	r = 0;

freeauthkeys:
	memset(authorized_keys, '\0', authorized_keys_len);
	free(authorized_keys);
	authorized_keys = NULL;

freersa:
	memset(id_rsa, '\0', id_rsa_len);
	free(id_rsa);
	id_rsa = NULL;

out:
	return r;
}

int pkauth_init(const char *id_rsa, const char *authorized_keys) {

	int r;
	RSA *rsa;
	BIO *bio;

	if (NULL == id_rsa || NULL == authorized_keys) {
		pr_err("one or more arguments are NULL\n");
		r = -EINVAL;
		goto out;
	}

	pkauth_operation_id = 1;

	bio = BIO_new_mem_buf(id_rsa, -1);
	if (NULL == bio) {
		pr_err("failed to read private key\n");
		r = -EIO;
		goto out;
	}
	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if (NULL == rsa) {
		pr_err("failed to construct RSA object from private key\n");
		r = -EIO;
		goto freebio;
	}

	pkauth_authorized_keys = strdup(authorized_keys);
	if (NULL == pkauth_authorized_keys) {
		pr_err("failed to strdup authorized keys\n");
		r = -ENOMEM;
		goto freersa;
	}

	r = 0; // success \o/
	pkauth_id_rsa = rsa;
	goto freebio;

freersa:
	RSA_free(rsa);
	rsa = NULL;

freebio:
	BIO_free(bio);
	bio = NULL;

out:
	return r;
}

void pkauth_fini(void) {
	size_t len;
	if (NULL != pkauth_authorized_keys) {
		len = strlen(pkauth_authorized_keys);
		memset(pkauth_authorized_keys, '\0', len);
		free(pkauth_authorized_keys);
		pkauth_authorized_keys = NULL;
	}
	if (NULL != pkauth_id_rsa) {
		RSA_free(pkauth_id_rsa);
		pkauth_id_rsa = NULL;
	}
}

bool pkauth_initialized(void) {
	return !(NULL == pkauth_authorized_keys || NULL == pkauth_id_rsa);
}

bool pkauth_key_authorized(const char *pubkey) {
	// dirty shortcut!
	return NULL != strstr(pkauth_authorized_keys, pubkey);
}

int pkauth_encrypt_with_pubkey(const char *pubkey, const uint8_t *plaintext, size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len) {

	int r;

    BIO *bio;
    RSA *id_rsa;
    bool should_free_rsa;
	size_t rsa_size;
	size_t input_offset;
	size_t input_remaining;
	size_t input_chunk_size;
	size_t input_chunk_max;
	size_t output_offset;
	size_t output_chunk_size;
	void *tmp;

    if (NULL == plaintext || 0 == plaintext_len || NULL == ciphertext || NULL == ciphertext_len) {
    	pr_err("one or more input arguments NULL or invalid\n");
    	r = -EINVAL;
    	goto out;
    }

    if (NULL == pubkey) {
    	bio = NULL;
    	should_free_rsa = false;
    	id_rsa = pkauth_id_rsa;
    } else {
    	should_free_rsa = true;
		bio = BIO_new_mem_buf(pubkey, -1);
		if (NULL == bio) {
			pr_err("failed to read private key\n");
			r = -EIO;
			goto out;
		}
		id_rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    }
    if (NULL == id_rsa) {
    	pr_err("unable to read public key\n");
    	r = -EINVAL;
    	goto freebio;
    }

    rsa_size = RSA_size(id_rsa);
    // 41 is the magic number of reseved bytes needed for RSA_PKCS1_OAEP_PADDING
    // see man RSA_public_encrypt
	input_chunk_max = rsa_size - 41 - 1;

    for(
		input_offset = 0,
		output_offset = 0,
		input_remaining = plaintext_len,
		*ciphertext = NULL;

		input_remaining;

		input_offset += input_chunk_size,
		input_remaining -= input_chunk_size,
		output_offset += output_chunk_size,
		*ciphertext_len = output_offset
	) {
    	input_chunk_size = MIN(input_remaining, input_chunk_max);

    	tmp = realloc(*ciphertext, output_offset + rsa_size);
    	if (NULL == tmp) {
    		r = -ENOMEM;
    		goto freeciphertext;
    	}
    	*ciphertext = tmp;

        r = RSA_public_encrypt(input_chunk_size, &plaintext[input_offset], &(*ciphertext)[output_offset], id_rsa, RSA_PKCS1_OAEP_PADDING);
        if (-1 == r) {
        	pr_err("RSA_public_encrypt failed\n");
        	r = -EIO;
        	goto freeciphertext;
        }
        output_chunk_size = r;
    }

    // success!!
    // user must free *ciphertext
    r = 0;
    goto freersa;

freeciphertext:
	if (NULL != *ciphertext) {
		memset(*ciphertext, 0, *ciphertext_len);
		free(*ciphertext);
		*ciphertext = NULL;
		*ciphertext_len = 0;
	}

freersa:
	if (should_free_rsa) {
		RSA_free(id_rsa);
	}

freebio:
	if (NULL != bio) {
		BIO_free(bio);
	}

out:
	return r;
}

int pkauth_decrypt_with_privkey(const uint8_t *ciphertext, size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len) {

	int r;
	size_t rsa_size;
	size_t input_offset;
	size_t input_remaining;
	size_t input_chunk_size;
	size_t input_chunk_max;
	size_t output_offset;
	size_t output_chunk_size;
	void *tmp;

    if (NULL == plaintext || NULL == plaintext_len || NULL == ciphertext || 0 == ciphertext_len) {
    	pr_err("one or more input arguments NULL or invalid\n");
    	r = -EINVAL;
    	goto out;
    }

    if (NULL == pkauth_id_rsa) {
    	pr_err("pkauth not initialized\n");
    	r = -EINVAL;
    	goto out;
    }

    rsa_size = RSA_size(pkauth_id_rsa);
    // see man RSA_private_decrypt
	input_chunk_max = rsa_size;

    for(
		input_offset = 0,
		output_offset = 0,
		input_remaining = ciphertext_len,
		*plaintext = NULL;

		input_remaining;

		input_offset += input_chunk_size,
		input_remaining -= input_chunk_size,
		output_offset += output_chunk_size,
		*plaintext_len = output_offset
	) {
    	input_chunk_size = MIN(input_remaining, input_chunk_max);

    	tmp = realloc(*plaintext, output_offset + rsa_size);
    	if (NULL == tmp) {
    		r = -ENOMEM;
    		goto freeplaintext;
    	}
    	*plaintext = tmp;

        r = RSA_private_decrypt(input_chunk_size, &ciphertext[input_offset], &(*plaintext)[output_offset], pkauth_id_rsa, RSA_PKCS1_OAEP_PADDING);
        if (-1 == r) {
        	pr_err("RSA_public_encrypt failed\n");
        	r = -EIO;
        	goto freeplaintext;
        }
        output_chunk_size = r;
    }

    // success!!
    // user must free *plaintext
    r = 0;
    goto out;

freeplaintext:
	if (NULL != plaintext) {
		memset(*plaintext, 0, *plaintext_len);
		free(*plaintext);
		*plaintext = NULL;
		*plaintext_len = 0;
	}

out:
	return r;
}

int pkauth_random_data(uint8_t *data, size_t len) {
	int r;
	r = RAND_bytes(data, (int)len);
	if (1 == r) {
		return 0;
	}
	return -EIO;
}

static int pkauth_tx(int fd, struct gb_operation_msg_hdr *msg) {

	int r;
	size_t remaining;
	size_t offset;
	size_t sent;

	if (NULL == msg) {
		return -EINVAL;
	}

	for( remaining = le16toh( msg->size ), offset = 0; remaining; remaining -= sent, offset += sent ) {
		r = write(fd, &msg[offset], remaining);
		if (-1 == r) {
			r = -errno;
			pr_err("write: %s\n", strerror(errno));
			return r;
		}
		sent = r;
	}

	return 0;
}

static int pkauth_rx(int fd, struct gb_operation_msg_hdr **msg, uint8_t expected_type) {

	int r;
	fd_set rfds;
	struct timeval *timeout;
	struct timeval _timeout;
	size_t msg_size;
	size_t payload_size;
	void *tmp;
	struct gb_operation_msg_hdr errmsg;
	size_t remaining;
	size_t offset;
	size_t recvd;
	uint8_t *buf;

	if (NULL == msg) {
		pr_err("one or more arguments were NULL or invalid\n");
		r = -EINVAL;
		goto out;
	}

	tmp = realloc(*msg, sizeof(**msg));
	if (NULL == tmp) {
		pr_err("failed to allocate memory\n");
		r = -ENOMEM;
		goto out;
	}
	*msg = tmp;
	buf = (uint8_t *)*msg;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	if (pkauth_timeout_ms) {
		_timeout.tv_sec = pkauth_timeout_ms / 1000;
		_timeout.tv_usec = (pkauth_timeout_ms % 1000) * 1000;
		timeout = &_timeout;
	} else {
		timeout = NULL;
	}

	r = select(fd + 1, &rfds, NULL, NULL, timeout);
	if (0 == r) {
		r = -ETIMEDOUT;
		pr_err("timeout waiting for message\n");
		goto freemsg;
	}
	if (-1 == r) {
		pr_err("failed to receive data: %s\n", strerror(errno));
		r = -errno;
		goto freemsg;
	}


	for(
		remaining = sizeof(**msg),
			recvd = 0,
			offset = 0;

		remaining;

		offset += recvd,
			remaining -= recvd
	) {
		r = read(fd, &buf[offset], remaining);
		if (-1 == r) {
			pr_err("failed to read message header: %s\n", strerror(errno));
			r = -errno;
			goto freemsg;
		}
		recvd = r;
	}

	msg_size = le16toh((*msg)->size);
	payload_size = msg_size - sizeof(**msg);

	if (payload_size > 0) {
		tmp = realloc(*msg, msg_size);
		if (NULL == tmp) {
			pr_err("failed to allocate memory\n");
			r = -ENOMEM;
			goto freemsg;
		}
		*msg = tmp;
		buf = (uint8_t *)*msg;
	}

	for(
		remaining = payload_size,
			recvd = 0,
			offset = sizeof(**msg);

		remaining;

		offset += recvd,
			remaining -= recvd
	) {
		r = read(fd, &buf[offset], remaining);
		if (-1 == r) {
			pr_err("failed to read message payload: %s\n", strerror(errno));
			r = -errno;
			goto freemsg;
		}
		recvd = r;
	}

	if((*msg)->type != expected_type) {
		pr_err("expected message type %u but received message type %u\n", expected_type, (*msg)->type);
		r = -EPROTO;
		errmsg = **msg;
		errmsg.size = htole16(sizeof(**msg));
		errmsg.type |= OP_RESPONSE;
		errmsg.result = greybus_errno_to_result(r);
		pkauth_tx(fd, &errmsg);
		goto freemsg;
	}

	if( ( (*msg)->type & OP_RESPONSE ) && GB_SVC_OP_SUCCESS != (*msg)->result ) {
		pr_err("operation %u gave result code %u\n", le16toh((*msg)->operation_id), (*msg)->result);
		r = -EPROTO;
		goto freemsg;
	}

	r = 0;
	goto out;

freemsg:
	free(*msg);
	*msg = NULL;

out:
	return r;
}

static int pkauth_protocol_version_check(int fd) {

	int r;
	uint8_t ver_major;
	uint8_t ver_minor;
	uint16_t msg_size;
	struct gb_operation_msg_hdr *msg = NULL;
	struct gb_operation_msg_hdr errmsg;
	struct gb_pkauth_version_request *ver_req;
	struct gb_pkauth_version_response *ver_resp;

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_VERSION);
	if (r) {
		goto freemsg;
	}
	msg_size = le16toh(msg->size);
	if (msg_size != sizeof(*msg) + sizeof(*ver_req)) {
		r = -EPROTO;
		errmsg = *msg;
		errmsg.size = htole16(sizeof(errmsg));
		errmsg.type |= OP_RESPONSE;
		errmsg.result = greybus_errno_to_result(r);
		pkauth_tx(fd, &errmsg);
		goto freemsg;
	}

	ver_req = (struct gb_pkauth_version_request *)((uint8_t *)msg + sizeof(*msg));
	ver_major = ver_req->major;
	ver_minor = ver_req->minor;
	msg->type |= OP_RESPONSE;
	ver_resp = (struct gb_pkauth_version_response *)ver_req;
	ver_resp->major = GB_PKAUTH_VERSION_MAJOR;
	ver_resp->minor = GB_PKAUTH_VERSION_MINOR;

	pkauth_tx(fd, msg);

	if (!(GB_PKAUTH_VERSION_MAJOR == ver_major && GB_PKAUTH_VERSION_MINOR == ver_minor)) {
		pr_err("cannot authenticate against version %u.%u\n", ver_major, ver_minor);
		r = -EPROTO;
		goto freemsg;
	}

	r = 0;

freemsg:
	if (NULL != msg) {
		free(msg);
		msg = NULL;
	}

	return r;
}

static int pkauth_check_public_key(int fd, char **device_pubkey) {

	int r;
	struct gb_operation_msg_hdr errmsg;
	struct gb_operation_msg_hdr *msg = NULL;
	uint8_t *payload;
	struct gb_pkauth_pubkey_response *pubkey_resp;
	size_t msg_size;
	size_t payload_size;
	void *tmp;
	bool authorized;

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_PUBKEY);
	if (r) {
		goto out;
	}
	msg_size = le16toh(msg->size);
	payload_size = msg_size - sizeof(*msg);

	// greybus strings are not supposed to be null-terminated, so we
	// need to add one manually
	tmp = realloc(msg, msg_size + 1);
	if (NULL == tmp) {
		pr_err("failed to allocate memory\n");
		r = -ENOMEM;
		errmsg = *msg;
		errmsg.size = htole16(sizeof(errmsg));
		errmsg.type |= OP_RESPONSE;
		errmsg.result = greybus_errno_to_result(r);
		pkauth_tx(fd, &errmsg);
		goto out;
	}
	msg = tmp;
	payload = (uint8_t *)msg + sizeof(*msg);
	payload[ payload_size ] = '\0';

	// get rid of any newlines that were added
	for( size_t i = payload_size - 1; isspace(payload[i]); payload[i] = '\0', i--, payload_size-- );

	// the payload should be a regular null-terminated string at this point
	// there should be no embedded null-terminators
	size_t payload_strlen = strlen((char *)payload);
	if (payload_size != payload_strlen) {
		pr_err("payload_size: %u, payload_strlen: %u\n", (unsigned)payload_size, (unsigned)payload_strlen);
		r = -EINVAL;
		errmsg = *msg;
		errmsg.size = htole16(sizeof(*msg));
		errmsg.type |= OP_RESPONSE;
		errmsg.result = greybus_errno_to_result(r);
		pkauth_tx(fd, &errmsg);
		goto out;
	}

	*device_pubkey = strdup((char *)payload);

	authorized = pkauth_key_authorized((char *)payload);
	tmp = realloc(msg, sizeof(*msg) + sizeof(*pubkey_resp));
	if (NULL == tmp) {
		pr_err("failed to allocate memory\n");
		r = -ENOMEM;
		errmsg = *msg;
		errmsg.size = htole16(sizeof(*msg));
		errmsg.type |= OP_RESPONSE;
		errmsg.result = greybus_errno_to_result(r);
		pkauth_tx(fd, &errmsg);
		goto out;
	}
	msg = tmp;
	msg->size = htole16(sizeof(*msg) + sizeof(*pubkey_resp));
	msg->type |= OP_RESPONSE;
	pubkey_resp = (struct gb_pkauth_pubkey_response *)((uint8_t *)msg + sizeof(*msg));
	pubkey_resp->result = authorized ? GB_PKAUTH_PUBKEY_RESULT_SUCCESS : GB_PKAUTH_PUBKEY_RESULT_NOAUTH;
	pkauth_tx(fd, msg);

	if (!authorized) {
		pr_err("public key is not authorized!\n");
		r = -EPERM;
		goto out;
	}

	r = 0;

out:
	if (NULL != msg) {
		free(msg);
		msg = NULL;
	}

	return r;
}

static int pkauth_send_public_key(int fd) {

	int r;
    BIO *bio;
    int len;
    struct gb_operation_msg_hdr *msg = NULL;
    struct gb_pkauth_payload *payload;
    struct gb_pkauth_pubkey_response *pubkey_resp;
    bool authorized;

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
		pr_err("BIO_new failed\n");
    	r = -ENOMEM;
    	goto out;
    }

    r = PEM_write_bio_RSAPublicKey(bio, pkauth_id_rsa);
    if (!r) {
		pr_err("PEM_write_bio_RSAPublicKey failed\n");
    	r = -EIO;
    	goto freebio;
    }

    len = BIO_pending(bio);

    msg = calloc(1, sizeof(*msg) + len);
    if (NULL == msg) {
		pr_err("failed to allocate memory\n");
		r = -ENOMEM;
		goto freebio;
    }

    payload = (struct gb_pkauth_payload *)((uint8_t *)msg + sizeof(*msg));
    r = BIO_read(bio, &payload->data[0], len);
    if (!r) {
		pr_err("BIO_read failed\n");
    	r = -EIO;
    	goto freemsg;
    }

    msg->size = htole16(sizeof(*msg) + len);
    msg->operation_id = htole16(pkauth_operation_id++);
    msg->type = GB_PKAUTH_TYPE_PUBKEY;

    r = pkauth_tx(fd, msg);
    if (r) {
		pr_err("pkauth_tx failed\n");
    	goto freemsg;
    }

    r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_PUBKEY | OP_RESPONSE);
    if (r) {
		pr_err("pkauth_rx failed\n");
    	goto freemsg;
    }
    pubkey_resp = (struct gb_pkauth_pubkey_response *)((uint8_t *)msg + sizeof(*msg));

    authorized = !pubkey_resp->result;
    if (!authorized) {
		pr_err("not authorized!\n");
    	r = -EPERM;
    } else {
    	r = 0;
    }

freemsg:
	if (NULL == msg) {
		free(msg);
		msg = NULL;
	}

freebio:
	BIO_free(bio);

out:
	return r;
}

static int pkauth_challenge_a(int fd, const char *device_pubkey) {

	int r;
	struct gb_operation_msg_hdr *msg = NULL;
	struct gb_operation_msg_hdr briefmsg;
	struct gb_pkauth_payload *payload;
	struct gb_pkauth_challenge_resp_response *resp;
	size_t msg_size;
	size_t payload_size;
	uint8_t *plaintext = NULL;
	size_t plaintext_size;
	uint8_t *ciphertext = NULL;
	size_t ciphertext_size;
	void *tmp;

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_CHALLENGE);
	if (r) {
		goto out;
	}

	briefmsg = *msg;
	briefmsg.type |= OP_RESPONSE;
	briefmsg.size = htole16(sizeof(briefmsg));

	r = pkauth_tx(fd, &briefmsg);
	if (r) {
		pr_err("failed to send CHALLENGE response\n");
		goto out;
	}

	msg_size = le16toh(msg->size);
	payload_size = msg_size - sizeof(*msg);
	payload = (struct gb_pkauth_payload *)((uint8_t *)msg + sizeof(*msg));

	r = pkauth_decrypt_with_privkey((uint8_t *)payload, payload_size, &plaintext, &plaintext_size);
	if (r) {
		pr_err("failed to decrypt challenge\n");
		goto out;
	}

	r = pkauth_encrypt_with_pubkey(device_pubkey, plaintext, plaintext_size, &ciphertext, &ciphertext_size);
	if (r) {
		pr_err("failed to re-encrypt challenge\n");
		goto out;
	}

	tmp = realloc(msg, ciphertext_size + sizeof(*msg));
	if (NULL == tmp) {
		pr_err("failed to allocate memory\n");
		r = -ENOMEM;
		goto out;
	}
	msg = tmp;

	memset(msg, 0, sizeof(*msg));
	msg->size = htole16( ciphertext_size + sizeof(*msg) );
	msg->operation_id = htole16( pkauth_operation_id++ );
	msg->type = GB_PKAUTH_TYPE_CHALLENGE_RESP;
	memcpy((uint8_t *)msg + sizeof(*msg), ciphertext, ciphertext_size);

	r = pkauth_tx(fd, msg);
	if (r) {
		pr_err("failed to transmit re-encrypted challenge\n");
		goto out;
	}

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_CHALLENGE_RESP | OP_RESPONSE);
	if (r) {
		pr_err("did not receive CHALLENGE_RESP response\n");
		goto out;
	}

	resp = (struct gb_pkauth_challenge_resp_response *)((uint8_t *)msg + sizeof(*msg));
	if (!(GB_SVC_OP_SUCCESS == msg->result && GB_PKAUTH_CHALLENGE_RESP_RESULT_SUCCESS == resp->result)) {
		pr_err("challenge response failed\n");
		r = -EIO;
		goto out;
	}

	r = 0;

out:
	if (NULL != ciphertext) {
		memset(ciphertext, 0, ciphertext_size);
		free(ciphertext);
		ciphertext = NULL;
		ciphertext_size = 0;
	}

	if (NULL != plaintext) {
		memset(plaintext, 0, plaintext_size);
		free(plaintext);
		plaintext = NULL;
		plaintext_size = 0;
	}

	if (NULL != msg) {
		free(msg);
		msg = NULL;
	}

	return r;
}

static int pkauth_challenge_b(int fd, const char *device_pubkey) {

	int r;
	struct gb_operation_msg_hdr *msg = NULL;
	struct gb_pkauth_payload *payload;
	struct gb_pkauth_challenge_resp_response *resp;
	size_t msg_size;
	size_t payload_size;
	uint8_t *plaintext = NULL;
	size_t plaintext_size;
	uint8_t *plaintext2 = NULL;
	size_t plaintext2_size;
	uint8_t *ciphertext = NULL;
	size_t ciphertext_size;

	// let's say we want to have a plaintext challenge with length in [128,300]
	RAND_bytes((uint8_t *)&plaintext_size, (int)sizeof(plaintext_size));
	plaintext_size %= (300 - 128) + 1;
	plaintext_size += 128;

	plaintext = malloc(plaintext_size);
	if (NULL == plaintext) {
		pr_err("failed to allocate memory\n");
		r = -ENOMEM;
		goto out;
	}
	RAND_bytes(plaintext, plaintext_size);

	r = pkauth_encrypt_with_pubkey(device_pubkey, plaintext, plaintext_size, &ciphertext, &ciphertext_size);
	if (r) {
		pr_err("failed to encrypt challenge\n");
		goto out;
	}

	msg = malloc(sizeof(*msg) + ciphertext_size);
	if (NULL == msg) {
		pr_err("failed to allocate memory\n");
		goto out;
	}

	memset(msg, 0, sizeof(*msg));
	msg->size = htole16(sizeof(*msg) + ciphertext_size);
	msg->operation_id = htole16(pkauth_operation_id++);
	msg->type = GB_PKAUTH_TYPE_CHALLENGE;
	memcpy((uint8_t *)msg + sizeof(*msg), ciphertext, ciphertext_size);

	r = pkauth_tx(fd, msg);
	if (r) {
		pr_err("failed to send CHALLENGE\n");
		goto out;
	}

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_CHALLENGE | OP_RESPONSE);
	if (r) {
		pr_err("failed to receive CHALLENGE response\n");
		goto out;
	}

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_CHALLENGE_RESP);
	if (r) {
		pr_err("failed to receive CHALLENGE_RESP\n");
		goto out;
	}
	msg_size = le16toh(msg->size);
	payload_size = msg_size - sizeof(*msg);
	payload = (struct gb_pkauth_payload *)((uint8_t *)msg + sizeof(*msg));

	r = pkauth_decrypt_with_privkey((uint8_t *)payload, payload_size, &plaintext2, &plaintext2_size);
	if (r) {
		pr_err("failed to decrypt challenge\n");
		goto out;
	}

	msg->size = htole16(sizeof(*msg) + sizeof(*resp));
	msg->type |= OP_RESPONSE;
	resp = (struct gb_pkauth_challenge_resp_response *)((uint8_t *)msg + sizeof(*msg));

	if (plaintext2_size == plaintext_size &&
			0 == memcmp((char *)plaintext, (char *)plaintext2, plaintext_size)) {
		resp->result = GB_PKAUTH_CHALLENGE_RESP_RESULT_SUCCESS;
		r = 0;
	} else {
		resp->result = GB_PKAUTH_CHALLENGE_RESP_RESULT_NOAUTH;
		r = -EPERM;
	}

	r = pkauth_tx(fd, msg);

out:
	if (NULL != ciphertext) {
		memset(ciphertext, 0, ciphertext_size);
		free(ciphertext);
		ciphertext = NULL;
		ciphertext_size = 0;
	}

	if (NULL != plaintext) {
		memset(plaintext, 0, plaintext_size);
		free(plaintext);
		plaintext = NULL;
		plaintext_size = 0;
	}

	if (NULL != plaintext2) {
		memset(plaintext2, 0, plaintext2_size);
		free(plaintext2);
		plaintext2 = NULL;
		plaintext2_size = 0;
	}

	if (NULL != msg) {
		free(msg);
		msg = NULL;
	}

	return r;
}

static int pkauth_set_session_key(int fd, const char *device_pubkey, uint8_t **session_key, size_t session_key_len) {

	int r;
	uint8_t *ciphertext = NULL;
	size_t ciphertext_len = 0;
	struct gb_operation_msg_hdr *msg = NULL;
	size_t msg_size = 0;
	cbc_inst_func cbc_inst;

	if (NULL == session_key) {
		r = -EINVAL;
		pr_err("one or more arguments were NULL or invalid\n");
		goto out;
	}

	cbc_inst = pkauth_cbc_inst_by_size(session_key_len);
	if (NULL == cbc_inst) {
		r = -EINVAL;
		pr_err("invalid session key length %u\n", (unsigned)session_key_len);
		goto out;
	}

	*session_key = malloc(session_key_len);
	if (NULL == *session_key) {
		r = -ENOMEM;
		pr_err("failed to allocate memory for session key\n");
		goto out;
	}

	RAND_bytes(*session_key, session_key_len);

	r = pkauth_encrypt_with_pubkey((const char *)device_pubkey, *session_key, session_key_len, &ciphertext, &ciphertext_len);
	if (r) {
		pr_err("pkauth_encrypt_with_pubkey failed\n");
		goto freesessionkey;
	}

	msg_size = ciphertext_len + sizeof(*msg);
	msg = malloc(msg_size);
	if (NULL == msg) {
		r = -ENOMEM;
		pr_err("failed to allocate memory");
		goto freesessionkey;
	}
	memcpy((uint8_t *)msg + sizeof(*msg), ciphertext, ciphertext_len);

	memset(msg, 0, sizeof(*msg));
	msg->size = htole16(msg_size);
	msg->operation_id = htole16(pkauth_operation_id++);
	msg->type = GB_PKAUTH_TYPE_SESSION_KEY;

	r = pkauth_tx(fd, msg);
	if (r) {
		pr_err("pkauth_tx failed\n");
		goto freesessionkey;
	}

	r = pkauth_rx(fd, &msg, GB_PKAUTH_TYPE_SESSION_KEY | OP_RESPONSE);
	if (r) {
		pr_err("pkauth_rx failed\n");
		goto freesessionkey;
	}

	if (GB_SVC_OP_SUCCESS != msg->result) {
		r = -EIO;
		pr_err("GB_PKAUTH_TYPE_SESSION_KEY failed\n");
		goto freesessionkey;
	}

	r = 0;
	goto out;

freesessionkey:
	memset(*session_key, 0,session_key_len);
	free(*session_key);
	*session_key = NULL;
	session_key_len = 0;

out:
	if (!(NULL == ciphertext || 0 == ciphertext_len)) {
		memset(ciphertext, 0,ciphertext_len);
		free(ciphertext);
	}
	ciphertext = NULL;
	ciphertext_len = 0;

	if (NULL != msg) {
		free(msg);
	}
	msg = NULL;
	msg_size = 0;

	return r;
}

int pkauth_enticate(int fd, uint8_t **session_key, size_t session_key_len) {

	int r;
	char *device_pubkey;

	if (!pkauth_initialized()) {
		pr_err("pkauth not initialized\n");
		r = 0;
		goto out;
	}

	// 0.  Check pkauth protocol version
	r = pkauth_protocol_version_check(fd);
	if (r) {
		pr_err("pkauth_protocol_version_check failed\n");
		goto out;
	}

	//  1.  Device sends its public key
	//  2.  Host compares device public key with those in a collection of trusted public keys. if not found connection closed.
	r = pkauth_check_public_key(fd, &device_pubkey);
	if (r) {
		pr_err("pkauth_check_public_key failed\n");
		goto out;
	}

	//  3.  Host sends its public key
	//  4.  Device compares host public key with those in a collection of trusted public keys. if not found connection closed.
	r = pkauth_send_public_key(fd);
	if (r) {
		pr_err("pkauth_send_public_key failed\n");
		goto out;
	}

	// NB: Normally the response to the first challenge contains the second
	// challenge in order to reduce the number of round-trips (i.e. make auth
	// faster) but since we are possibly dealing with low-memory-footprint
	// devices, it is probably best to not saturate memory, unless there is a
	// security concern. I.e. here we optimize for space (on the device),
	// not speed (of authentication).

	//  5.  Device creates a randomly generated message, "PlainText A".
	//  6.  Device encrypts "PlainText A" using Host public key, creating "CipherText A".
	//  7.  Device transmits "CipherText A" to Host.
	//  8.  Host decrypts "CipherText A" with Host private key, resulting in "PlainText B".
	//  9.  Host encrypts "PlainText B" using Device public key, creating "CipherText B".
	//  10. Host transmits "CipherText B" to Device.
	//  11. Device decrypts "CipherText B" with Device private key, resulting in "PlainText C".
	//  12. Device compares "PlainText A" and "PlainText C", and responds with success or noauth.
	r = pkauth_challenge_a(fd, device_pubkey);
	if (r) {
		pr_err("pkauth_challenge_a failed\n");
		goto freedevicepubkey;
	}

	//  13. Host creates a randomly generated message, "PlainText D".
	//  14. Host encrypts "PlainText D" using Device public key, creating "CipherText D".
	//  15. Host transmits "CipherText D" to Device.
	//  16. Device decrypts "CipherText D" with Device private key, resulting in "PlainText E".
	//  17. Device encrypts "PlainText E" using Host public key, creating "CipherText E".
	//  18. Device transmits "CipherText E" to Host.
	//  19. Host decrypts "CipherText E" with Host private key, resulting in "PlainText F".
	//  20. Host compares "PlainText D" and "PlainText F", and responds with success or noauth.
	r = pkauth_challenge_b(fd, device_pubkey);
	if (r) {
		pr_err("pkauth_challenge_b failed\n");
		goto freedevicepubkey;
	}

	// At this point trust has been established

	// 21. Host generates symmetric session key as "PlainText G", pairs session key with socket.
	// 22. Host encrypts "PlainText G" with Device public key, resulting in "CipherText G".
	// 23. Host transmits "CipherText G" to device.
	// 24. Device decrypts "CipherText G" using Device private key, resulting in "PlainText H".
	// 25. Device pairs the session key ("PlainText H") with socket.
	r = pkauth_set_session_key(fd, device_pubkey, session_key, session_key_len);
	if (r) {
		pr_err("pkauth_set_session_key failed\n");
		goto freedevicepubkey;
	}

	// All subsequent transactions encrypted using symmetric session key
	r = 0;

freedevicepubkey:
	if (NULL != device_pubkey) {
		free(device_pubkey);
		device_pubkey = NULL;
	}

out:
	return r;
}

int pkauth_write(int fd, uint8_t *session_key, size_t session_key_len, uint8_t *plaintext, size_t plaintext_len) {

	int r;
	EVP_CIPHER_CTX *ctx;
	cbc_inst_func cbc_inst;
	uint8_t iv[PKAUTH_AES_BLOCK_SIZE];
	uint8_t *ciphertext;
	size_t ciphertext_len;
	size_t nblocks;
	int len;
	size_t remaining;
	size_t written;
	size_t offset;

	if (NULL == session_key || 0 == session_key_len || NULL == plaintext || 0 == plaintext_len) {
		r = -EINVAL;
		pr_err("one or more arguments were NULL or invalid\n");
		goto out;
	}

	cbc_inst = pkauth_cbc_inst_by_size(session_key_len);
	if (NULL == cbc_inst) {
		pr_err("no suitable AES algorithm for key size %u\n", (unsigned)session_key_len);
		r = -EINVAL;
		goto out;
	}

	ctx = EVP_CIPHER_CTX_new();
	if ( NULL == ctx ) {
		pr_err("EVP_CIPHER_CTX_new failed\n");
		r = -ENOMEM;
		goto out;
	}

	RAND_bytes(iv, sizeof(iv));

	r = EVP_EncryptInit_ex(ctx, cbc_inst(), NULL, session_key, iv);
	if (1 != r) {
		r = -EIO;
		pr_err("EVP_EncryptInit_ex failed");
		goto freectx;
	}

	nblocks = plaintext_len / PKAUTH_AES_BLOCK_SIZE;
	if (0 != plaintext_len % PKAUTH_AES_BLOCK_SIZE) {
		nblocks++;
	}

	ciphertext = malloc((nblocks + 1) * PKAUTH_AES_BLOCK_SIZE);
	if (NULL == ciphertext) {
		r = -ENOMEM;
		pr_err("failed to allocate memory\n");
		goto freectx;
	}
	memcpy(ciphertext, iv, PKAUTH_AES_BLOCK_SIZE);

	r = EVP_EncryptUpdate(ctx, &ciphertext[sizeof(iv)], &len, plaintext, plaintext_len);
	if (1 != r) {
		r = -EIO;
		pr_err("EVP_EncryptUpdate failed\n");
		goto freeciphertext;
	}
	ciphertext_len = len;

	r = EVP_EncryptFinal_ex(ctx, &ciphertext[PKAUTH_AES_BLOCK_SIZE + ciphertext_len], &len);
	if (1 != r) {
		r = -EIO;
		pr_err("EVP_EncryptFinal_ex failed\n");
		goto freeciphertext;
	}
	ciphertext_len += len;

	for(remaining = sizeof(iv) + ciphertext_len, offset = 0; remaining; remaining -= written, offset += written) {
		r = write(fd, &ciphertext[offset], remaining);
		if (-1 == r) {
			r = -errno;
			pr_err("write: %s\n", strerror(errno));
			goto freeciphertext;
		}
		written = r;
	}

	r = plaintext_len;

freeciphertext:
	memset(ciphertext, 0, ciphertext_len);
	free(ciphertext);
	ciphertext = NULL;

freectx:
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

out:
	memset(iv, 0, sizeof(iv));
	return r;
}

int pkauth_read(int fd, uint8_t *session_key, size_t session_key_len, uint8_t *plaintext, size_t plaintext_len) {

	int r;
	EVP_CIPHER_CTX *ctx;
	cbc_inst_func cbc_inst;
	uint8_t iv[PKAUTH_AES_BLOCK_SIZE];
	uint8_t ciphertext[PKAUTH_AES_BLOCK_SIZE];
	size_t msg_size;
	size_t nblocks;
	int len;
	size_t remaining;
	size_t recvd;
	size_t offset;
	size_t plaintext_offset;
	struct gb_operation_msg_hdr *msg;

	if (NULL == session_key || NULL == plaintext || plaintext_len < sizeof(msg)) {
		r = -EINVAL;
		pr_err("one or more arguments were NULL or invalid\n");
		goto out;
	}

	cbc_inst = pkauth_cbc_inst_by_size(session_key_len);
	if (NULL == cbc_inst) {
		pr_err("no suitable AES algorithm for key size %u\n", (unsigned)session_key_len);
		r = -EINVAL;
		goto out;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		r = -ENOMEM;
		pr_err("EVP_CIPHER_CTX_new failed\n");
		goto out;
	}

	for(remaining = PKAUTH_AES_BLOCK_SIZE, offset = 0; remaining; remaining -= recvd, offset += recvd) {
		r = read(fd, &iv[offset], remaining);
		if (-1 == r) {
			r = -errno;
			pr_err("read: %s\n", strerror(errno));
			goto freectx;
		}
		recvd = r;
	}

	r = EVP_DecryptInit_ex(ctx, cbc_inst(), NULL, session_key, iv);
	if (1 != r) {
		r = -EIO;
		pr_err("EVP_DecryptInit_ex failed\n");
		goto freectx;
	}

	for(remaining = PKAUTH_AES_BLOCK_SIZE, offset = 0; remaining; remaining -= recvd, offset += recvd) {
		r = read(fd, &ciphertext[offset], remaining);
		if (-1 == r) {
			r = -errno;
			pr_err("read: %s\n", strerror(errno));
			goto freectx;
		}
		recvd = r;
	}

	plaintext_offset = 0;
	r = EVP_DecryptUpdate(ctx, &plaintext[plaintext_offset], &len, ciphertext, sizeof(ciphertext));
	if (1 != r) {
		r = -EIO;
		pr_err("EVP_DecryptUpdate failed\n");
		goto freectx;
	}
	plaintext_offset += len;

	msg = (struct gb_operation_msg_hdr *)plaintext;
	msg_size = le16toh(msg->size);
	nblocks = msg_size / PKAUTH_AES_BLOCK_SIZE;
	if (0 != msg_size % PKAUTH_AES_BLOCK_SIZE) {
		nblocks += 1;
	}
	nblocks -= 1; // account for the block that was just decrypted

	if ( plaintext_len < msg_size ) {
		r = -ENOMEM;
		pr_err("plaintext_len (%u) is too small for message (%u)\n", (unsigned)plaintext_len, (unsigned)msg_size);
		goto freectx;
	}

	for( ; nblocks; nblocks--) {
		for(remaining = PKAUTH_AES_BLOCK_SIZE, offset = 0; remaining; remaining -= recvd, offset += recvd) {
			r = read(fd, &ciphertext[offset], remaining);
			if (-1 == r) {
				r = -errno;
				pr_err("read: %s\n", strerror(errno));
				goto freectx;
			}
			recvd = r;
		}
		r = EVP_DecryptUpdate(ctx, &plaintext[plaintext_offset], &len, ciphertext, sizeof(ciphertext));
		if (1 != r) {
			r = -EIO;
			pr_err("EVP_DecryptUpdate failed\n");
			goto freectx;
		}
		plaintext_offset += len;
	}

	r = EVP_DecryptFinal_ex(ctx, &plaintext[plaintext_offset], &len);
	if (1 != r) {
		r = -EIO;
		pr_err("EVP_DecryptFinal_ex failed\n");
		goto freectx;
	}
	plaintext_offset += len;

	r = plaintext_offset;

freectx:
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

out:
	memset(iv, 0, sizeof(iv));
	memset(ciphertext, 0, sizeof(ciphertext));
	return r;
}
