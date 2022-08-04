#include "variables.h"
#include "u2f_hid.h"
#include "utils.h"
#include "keys.h"
#include <uECC.h>
#include <sha256.h>

void handle_authenticate()
{
	uint8_t p1 = message[2];
	int idx = 7;
	uint8_t challenge_param[32], application_param[32];
	memcpy(challenge_param, message + idx, 32);
	idx += 32;
	memcpy(application_param, message + idx, 32);
	idx += 32;

	uint8_t key_handle_len = message[idx];
	idx++;
	// validate that key_handle_len is 48
	if (key_handle_len != 48)
	{
		data_len = 2;
		message[0] = (SW_WRONG_DATA >> 8) & 0xFF;
		message[1] = SW_WRONG_DATA & 0xFF;
		send_response();
		return;
	}
	uint8_t nonce[16];
	uint8_t mac[32];
	memcpy(nonce, message + idx, 16);
	idx += 16;
	memcpy(mac, message + idx, 32);

	Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
	sha_write(application_param, 32);
	sha_write(nonce, 16);
	uint8_t private_key[32];
	memcpy(private_key, Sha256.resultHmac(), 32);

	Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
	sha_write(application_param, 32);
	sha_write(private_key, 32);
	uint8_t computed_mac[32];
	memcpy(computed_mac, Sha256.resultHmac(), 32);

	if (memcmp(mac, computed_mac, 32) != 0)
	{
		data_len = 2;
		message[0] = (SW_WRONG_DATA >> 8) & 0xFF;
		message[1] = SW_WRONG_DATA & 0xFF;
		send_response();
		return;
	}
	if (p1 == 0x07) // check only
	{
		// already verified key handle above, so we just return success
		data_len = 2;
		message[0] = (SW_CONDITIONS_NOT_SATISFIED >> 8) & 0xFF;
		message[1] = SW_CONDITIONS_NOT_SATISFIED & 0xFF;
		send_response();
	}
	else if (p1 == 0x03 || p1 == 0x08)
	{
		int counter = counter_storage.read();
		uint8_t counter_bytes[4];
		counter_bytes[0] = (counter >> 24) & 0xFF;
		counter_bytes[1] = (counter >> 16) & 0xFF;
		counter_bytes[2] = (counter >> 8) & 0xFF;
		counter_bytes[3] = counter & 0xFF;

		Serial.println("counter:");
		Serial.println(counter);
		print_buffer(counter_bytes, 4);

		uint8_t user_presence = p1 == 0x03 ? 0x01 : 0x00;

		Sha256.init();
		sha_write(application_param, 32);
		Sha256.write(user_presence);
		sha_write(counter_bytes, 4);
		sha_write(challenge_param, 32);
		uint8_t message_hash[32];
		memcpy(message_hash, Sha256.result(), 32);

		uint8_t signature[64];
		uECC_sign(private_key, message_hash, 32, signature, uECC_secp256r1());

		// enforce user presence for 0x03
		if (p1 == 0x03)
		{
			confirm_user_presence();
		}

		int idx = 0;
		message[idx] = user_presence;
		idx++;
		memcpy(message + idx, counter_bytes, 4);
		idx += 4;

		idx = format_signature(idx, signature);

		data_len = idx;

		counter_storage.write(counter + 1);
		send_response();
	}
}