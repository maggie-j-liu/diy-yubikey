#include "variables.h"
#include "u2f_hid.h"
#include "utils.h"
#include "keys.h"
#include <uECC.h>
#include <sha256.h>

void sha_write(uint8_t *data, int len)
{
	for (int i = 0; i < len; i++)
	{
		Sha256.write(data[i]);
	}
}

// converts signature to asn.1 format and adds it to the message, starting at idx
int sig_to_asn1(int idx, uint8_t *signature)
{
	message[idx] = 0x30;
	idx++;
	int b1_idx = idx;
	idx++;
	uint8_t b1 = 68;
	for (int i = 0; i < 2; i++)
	{
		message[idx] = 0x02;
		idx++;
		if (signature[i * 32] > 0x7F)
		{
			message[idx] = 33;
			idx++;
			message[idx] = 0;
			idx++;
			b1++;
		}
		else
		{
			message[idx] = 32;
			idx++;
		}
		memcpy(message + idx, signature + i * 32, 32); // copy r or s value
		idx += 32;
	}

	message[b1_idx] = b1;

	message[idx] = (SW_NO_ERROR >> 8) & 0xFF;
	idx++;
	message[idx] = SW_NO_ERROR & 0xFF;
	idx++;
	return idx;
}

void handle_msg()
{
	uint8_t ins = message[1];
	uint8_t p1 = message[2];
	if (ins == U2F_REGISTER)
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

		// convert signature to asn.1 format
		idx = sig_to_asn1(idx, signature);

		data_len = idx;

		// confirm user presence
		for (int i = 0; i < strip.numPixels(); i++)
		{
			strip.setPixelColor(i, strip.Color(0, 0, 255));
		}
		strip.show();

		while (true)
		{
			uint16_t touch2 = touch_pad_2.measure();
			if (touch2 > 500)
			{
				Serial.print("QT 2: ");
				Serial.println(touch2);
				for (int i = 0; i < strip.numPixels(); i++)
				{
					strip.setPixelColor(i, strip.Color(255, 0, 0));
				}
				strip.show();
				break;
			}
		}
		send_response();
		return;
	}
	else if (ins == U2F_AUTHENTICATE)
	{
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
			return;
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
				for (int i = 0; i < strip.numPixels(); i++)
				{
					strip.setPixelColor(i, strip.Color(0, 0, 255));
				}
				strip.show();
				while (true)
				{
					uint16_t touch2 = touch_pad_2.measure();
					if (touch2 > 500)
					{
						Serial.print("QT 2: ");
						Serial.println(touch2);
						for (int i = 0; i < strip.numPixels(); i++)
						{
							strip.setPixelColor(i, strip.Color(255, 0, 0));
						}
						strip.show();
						break;
					}
				}
			}

			int idx = 0;
			message[idx] = user_presence;
			idx++;
			memcpy(message + idx, counter_bytes, 4);
			idx += 4;

			// convert signature to asn.1 format
			idx = sig_to_asn1(idx, signature);

			data_len = idx;

			counter_storage.write(counter + 1);
			send_response();
			return;
		}
	}
	else if (ins == U2F_VERSION)
	{
		data_len = 8;
		memcpy(message, "U2F_V2", 6);
		message[6] = (SW_NO_ERROR >> 8) & 0xFF;
		message[7] = SW_NO_ERROR & 0xFF;
		send_response();
		return;
	}
	else
	{
		// unknown instruction
		Serial.println("ERROR: UNKNOWN U2F COMMAND");
		data_len = 2;
		message[0] = (SW_INS_NOT_SUPPORTED >> 8) & 0xFF;
		message[1] = SW_INS_NOT_SUPPORTED & 0xFF;
		send_response();
		return;
	}
}