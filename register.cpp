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

	// generate a random nonce
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

	uECC_compute_public_key(private_key, public_key + 1, uECC_secp256r1());

	// run the application param and the newly generated private key and run them through hmac-sha256 again, using the same master key
	// the result is MAC used in the key handle
	Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
	sha_write(application_param, 32);
	sha_write(private_key, 32);
	uint8_t mac[32];
	memcpy(mac, Sha256.resultHmac(), 32);

	int idx = 0;
	// a reserved byte, which for legacy reasons has the value 0x05
	message[idx] = 0x05;
	idx++;

	// user public key
	memcpy(message + idx, public_key, 65);
	idx += 65;

	// length of key handle
	message[idx] = 16 + 32;
	idx++;

	// key handle, made up of the random nonce and the MAC
	memcpy(message + idx, nonce, 16);
	idx += 16;
	memcpy(message + idx, mac, 32);
	idx += 32;

	// attestation certificate
	memcpy(message + idx, ATTESTATION_CERT, sizeof(ATTESTATION_CERT));
	idx += sizeof(ATTESTATION_CERT);

	// generate signature

	Sha256.init();
	uint8_t reserved = 0x00;
	Sha256.write(reserved);
	sha_write(application_param, 32);
	sha_write(challenge_param, 32);
	sha_write(nonce, 16);
	sha_write(mac, 32);
	sha_write(public_key, 65);
	uint8_t message_hash[32];
	memcpy(message_hash, Sha256.result(), 32);

	uint8_t signature[64];
	uECC_sign(ATTESTATION_KEY, message_hash, 32, signature, uECC_secp256r1());

	idx = format_signature(idx, signature);

	data_len = idx;

	confirm_user_presence();

	send_response();
}