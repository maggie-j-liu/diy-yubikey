#include "variables.h"
#include "u2f_hid.h"
#include "utils.h"
#include <uECC.h>
#include <sha256.h>
#include "keys.h"

void handle_register()
{
	// validate that req_data_len == 64
	int req_data_len = (message[4] << 16) | (message[5] << 8) | message[6];
	if (req_data_len != 64)
	{
		data_len = 2;
		message[0] = (SW_WRONG_LENGTH >> 8) & 0xFF;
		message[1] = SW_WRONG_LENGTH & 0xFF;
		send_response();
		return;
	}

	// yubico's key wrapping algorithm
	// https://www.yubico.com/blog/yubicos-u2f-key-wrapping/

	uint8_t challenge_param[32], application_param[32];
	memcpy(challenge_param, message + 7, 32);
	memcpy(application_param, message + 7 + 32, 32);

	uint8_t public_key[65];
	public_key[0] = 0x04;

	// generate a random nonce of 16 bytes
	uint8_t nonce[16];
	for (int i = 0; i < 16; i++)
	{
		nonce[i] = random(256) & 0xFF;
	}

	// use the application param and random nonce and run them through hmac-sha256 using the master key
	// the output is the private key
	Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
	sha_write(application_param, 32);
	sha_write(nonce, 16);
	uint8_t private_key[32];
	memcpy(private_key, Sha256.resultHmac(), 32);

	// compute the public key from the private key
	uECC_compute_public_key(private_key, public_key + 1, uECC_secp256r1());

	// run the application param and the newly generated private key and run them through hmac-sha256 again, using the same master key
	// the result is the MAC used in the key handle
	Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
	sha_write(application_param, 32);
	sha_write(private_key, 32);
	uint8_t mac[32];
	memcpy(mac, Sha256.resultHmac(), 32);

	int idx = 0;

	// A reserved byte [1 byte], which for legacy reasons has the value 0x05.
	message[idx] = 0x05;
	idx++;

	// A user public key [65 bytes].
	memcpy(message + idx, public_key, 65);
	idx += 65;

	// A key handle length byte [1 byte], which specifies the length of the key handle
	message[idx] = 16 + 32;
	idx++;

	// A key handle, made up of the random nonce and the MAC
	memcpy(message + idx, nonce, 16);
	idx += 16;
	memcpy(message + idx, mac, 32);
	idx += 32;

	// An attestation certificate
	memcpy(message + idx, ATTESTATION_CERT, sizeof(ATTESTATION_CERT));
	idx += sizeof(ATTESTATION_CERT);

	// a signature [variable length, 71-73 bytes]. This is a ECDSA signature (on P-256) over the following byte string:
	// to generate a signature, we first hash it with sha256, then use the uECC_sign function
	Sha256.init();

	// A byte reserved for future use [1 byte] with the value 0x00.
	uint8_t reserved = 0x00;
	Sha256.write(reserved);

	// The application parameter [32 bytes] from the registration request message.
	sha_write(application_param, 32);

	// The challenge parameter [32 bytes] from the registration request message.
	sha_write(challenge_param, 32);

	// The above key handle, which is the nonce + MAC
	sha_write(nonce, 16);
	sha_write(mac, 32);

	// The above user public key [65 bytes].
	sha_write(public_key, 65);

	// get the hash
	uint8_t message_hash[32];
	memcpy(message_hash, Sha256.result(), 32);

	uint8_t signature[64];

	// sign the hash with the private key from the attestation certificate
	uECC_sign(ATTESTATION_KEY, message_hash, 32, signature, uECC_secp256r1());

	// put signature in correct format
	idx = format_signature(idx, signature);

	// set the message length, to be used in the send_response function
	data_len = idx;

	// change the leds to blue and wait for user interaction
	confirm_user_presence();

	// send the response
	send_response();
}