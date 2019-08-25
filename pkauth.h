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
#ifndef PKAUTH_H_
#define PKAUTH_H_

#include <stdbool.h>
#include <stdint.h>

#include <linux/types.h>

#ifndef __packed
#define __packed  __attribute__((__packed__))
#endif

#include "greybus_protocols.h"

/* Greybus public key authentication types */
#define GB_PKAUTH_TYPE_VERSION          0x7b
#define GB_PKAUTH_TYPE_PUBKEY           0x7c
#define GB_PKAUTH_TYPE_CHALLENGE        0x7d
#define GB_PKAUTH_TYPE_CHALLENGE_RESP   0x7e

#define GB_PKAUTH_VERSION_MAJOR 0x00
#define GB_PKAUTH_VERSION_MINOR 0x01

struct gb_pkauth_version_request {
	__u8	major;
	__u8	minor;
} __packed;

struct gb_pkauth_version_response {
	__u8	major;
	__u8	minor;
} __packed;

#define GB_PKAUTH_PUBKEY_RESULT_SUCCESS 0x00
#define GB_PKAUTH_PUBKEY_RESULT_NOAUTH  0x01

struct gb_pkauth_pubkey_response {
	__u8    result;
};

#define GB_PKAUTH_CHALLENGE_RESP_RESULT_SUCCESS 0x00
#define GB_PKAUTH_CHALLENGE_RESP_RESULT_NOAUTH  0x01

/* sent in response to a CHALLENGE_RESP message */
struct gb_pkauth_challenge_resp_response {
	__u8    result;
};

/* common for all other request and response types */
struct gb_pkauth_payload {
	__u8    data[0];
} __packed;

/**
 * Initialize public-key authentication
 *
 * This method of public key authentication is limited to RSA keys. The keys
 * will not work if there is an additional password required.
 *
 * The argument id_rsa is an RSA private key in PEM format, exactly like the
 * ~/.ssh/id_rsa file used in ssh. The RSA private key contains both the
 * private key as well as the public keys (i.e. a key pair). Such keys can be
 * generated using the command below.
 *
 * ssh-keygen -b <bits> -t rsa -C <descriptive comment> -f <output keyfile>
 *
 * The argument authorized_keys is, however, unlike the ~/.ssh/authorized_keys
 * file in ssh. Rather, it is a concatenation of public keys in PEM format.
 * Such public keys can be exported from a private key using the command below.
 *
 * ssh-keygen -e -m PEM -f <path to private key>
 *
 * Authorized keys can be separated by arbitrary characters, but the line
 * separator within the public key must be "\n" (not "\r\n") for compatibility
 * reasons.
 *
 * @param id_rsa the RSA private key (also contains the public key)
 * @param authorized_keys a concatenation of authorized RSA public keys
 *
 * @return 0 on success or a negative errno value on failure
 */
int pkauth_init(const char *id_rsa, const char *authorized_keys);

/**
 * Initialize public-key authentication from file
 *
 * @param id_rsa_file path to id_rsa file
 * @param authorized_keys_file path to authorized_keys file
 *
 * @return 0 on success, a negative errno value on failure
 */
int pkauth_init_from(const char *id_rsa_file, const char *authorized_keys_file);

/**
 * Set public-key authentation RX timeout (in milliseconds)
 *
 * @param timeout the timeout in milliseconds (0 is infinite)
 */
void pkauth_set_timeout_ms(unsigned timeout);

/**
 * Finalize public key authentication
 *
 * This function frees all resources associated with public key
 * authentication.
 */
void pkauth_fini(void);
/**
 * Check if pkauth has been initialized
 *
 * @return true if pkauth was successfully initialized
 */
bool pkauth_initialized(void);
/**
 * Check if a particular public key is authorized.
 *
 * @param pubkey the public key to check
 *
 * @return true if the public key is authorized, otherwise false
 */
bool pkauth_key_authorized(const char *pubkey);
/**
 * Generate a random sequence.
 *
 * @param data the output buffer
 * @param len the length of the output buffer
 *
 * @return 0 on success, otherwise a negative errno value
 */
int pkauth_random_data(uint8_t *data, size_t len);
/**
 * Encrypt a sequence with a public key
 *
 * The pubkey argument is optional. If it is NULL, then the public key portion
 * of the key provided in pkauth_init is used instead.
 *
 * @param pubkey the public key to use for encryption, or NULL for the default
 * @param plaintext the input message
 * @param plaintext_len length of the input message
 * @param ciphertext an output variable for the encrypted message
 * @param ciphertext_len an output variable for the encrypted message length
 *
 * @return 0 on success, otherwise a negative errno value on failure
 */
int pkauth_encrypt_with_pubkey(const char *pubkey, const uint8_t *plaintext, size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len);
/**
 * Decrypt an encrypted message
 *
 * This function always uses the private key portion of the key provided in
 * pkauth_init.
 *
 * @param ciphertext the (encrypted) input message
 * @param ciphertext_len length of the input message
 * @param plaintext an output variable for the decrypted message
 * @param plaintext_len an output variable for the decrypted message length
 *
 * @return 0 on success, otherwise a negative errno value on failure
 */
int pkauth_decrypt_with_privkey(const uint8_t *ciphertext, size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len);

/**
 * Authenticate with device over socket
 *
 * @param fd the file descriptor representing the connection
 *
 * @return 0 on success, otherwise a negative errno value on failure
 */
int pkauth_enticate(int fd);
#endif /* PKAUTH_H_ */
