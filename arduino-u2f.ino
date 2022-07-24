#include <Adafruit_TinyUSB.h>
#include "u2f_hid.h"
#include <uECC.h>
#include "keys.h"
#include <sha256.h>
#include <FlashStorage.h>

uint8_t const desc_hid_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

// USB HID object.
// desc report, desc len, protocol, interval, use out endpoint
Adafruit_USBD_HID usb_hid(desc_hid_report, sizeof(desc_hid_report), HID_ITF_PROTOCOL_NONE, 1, true);

FlashStorage(counter_storage, int);

void print_buffer(uint8_t const *buffer, int size = PACKET_SIZE)
{
	for (int i = 0; i < size; i++)
	{
		Serial.print(buffer[i], HEX);
		Serial.print(" ");
	}
}

int rng_func(uint8_t *dest, unsigned size)
{
	for (int i = 0; i < size; i++)
	{
		dest[i] = random(256);
	}
	return 1;
}

void setup()
{
	Serial.begin(115200);

	randomSeed(analogRead(0));
	usb_hid.setReportCallback(NULL, set_report_callback);
	usb_hid.begin();

	while (!TinyUSBDevice.mounted())
	{
		delay(1);
	}
	uECC_set_rng(rng_func);
}

void loop()
{
}

int write(uint8_t const *buffer)
{
	return usb_hid.sendReport(0, buffer, PACKET_SIZE);
}

bool processing_message = false;
int cid;
int data_len;
uint8_t cmd;
uint8_t message[7609]; // max message payload is 7609 bytes
int data_cursor;
uint8_t next_cont_packet = 0;

void send_response()
{
	uint8_t packet[PACKET_SIZE];
	packet[0] = (cid >> 24) & 0xFF;
	packet[1] = (cid >> 16) & 0xFF;
	packet[2] = (cid >> 8) & 0xFF;
	packet[3] = cid & 0xFF;
	packet[4] = cmd;
	packet[5] = (data_len >> 8) & 0xFF;
	packet[6] = data_len & 0xFF;
	int included = min(PACKET_SIZE - 7, data_len);
	memcpy(packet + 7, message, included);
	next_cont_packet = 0;
	usb_hid.sendReport(0, packet, PACKET_SIZE);

	while (included < data_len)
	{
		while (!tud_hid_ready())
		{
			delay(1);
			tud_task(); // important! otherwise tud_hid_ready will always be false
		}
		packet[4] = next_cont_packet;
		int to_include = min(PACKET_SIZE - 5, data_len - included);
		memcpy(packet + 5, message + included, to_include);
		usb_hid.sendReport(0, packet, PACKET_SIZE);
		next_cont_packet += 1;
		included += to_include;
	}
}

void handle_init()
{
	int new_cid = 1;
	data_len = 17;
	// since we are using message as the response buffer, the nonce doesn't change
	message[8] = (new_cid >> 24) & 0xFF;
	message[9] = (new_cid >> 16) & 0xFF;
	message[10] = (new_cid >> 8) & 0xFF;
	message[11] = new_cid & 0xFF;
	message[12] = U2FHID_IF_VERSION; // protocol version
	message[13] = 1;				 // major version
	message[14] = 0;				 // minor version
	message[15] = 1;				 // device version
	message[16] = 0;				 // capabilities
	send_response();
}

void handle_msg()
{
	uint8_t ins = message[1];
	uint8_t p1 = message[2];
	if (ins == U2F_REGISTER)
	{
		int req_data_len = (message[4] << 16) | (message[5] << 8) | message[6];
		// TODO: validate that req_data_len == 64

		// yubico's key wrapping algorithm
		// https://www.yubico.com/blog/yubicos-u2f-key-wrapping/

		uint8_t challenge_param[32], application_param[32];
		memcpy(challenge_param, message + 7, 32);
		memcpy(application_param, message + 7 + 32, 32);
		uint8_t public_key[65];
		// uint8_t private_key[32];
		public_key[0] = 0x04;
		// print_buffer(public_key, 65);
		// uECC_make_key(public_key + 1, private_key, uECC_secp256r1());
		uint8_t nonce[16];
		for (int i = 0; i < 16; i++)
		{
			nonce[i] = random(256) & 0xFF;
		}
		Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(application_param[i]);
		}
		for (int i = 0; i < 16; i++)
		{
			Sha256.write(nonce[i]);
		}
		uint8_t private_key[32];
		memcpy(private_key, Sha256.resultHmac(), 32);
		int computed = uECC_compute_public_key(private_key, public_key + 1, uECC_secp256r1());

		Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(application_param[i]);
		}
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(private_key[i]);
		}
		uint8_t mac[32];
		memcpy(mac, Sha256.resultHmac(), 32);

		int idx = 0;
		message[idx] = 0x05;
		idx++;
		memcpy(message + idx, public_key, 65);
		idx += 65;
		message[idx] = 16 + 32; // length of key handle
		idx++;
		memcpy(message + idx, nonce, 16);
		idx += 16;
		memcpy(message + idx, mac, 32);
		idx += 32;
		memcpy(message + idx, ATTESTATION_CERT, 319);
		idx += 319;

		Sha256.init();
		uint8_t reserved = 0x00;
		Sha256.write(reserved);
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(application_param[i]);
		}
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(challenge_param[i]);
		}
		for (int i = 0; i < 16; i++)
		{
			Sha256.write(nonce[i]);
		}
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(mac[i]);
		}
		for (int i = 0; i < 65; i++)
		{
			Sha256.write(public_key[i]);
		}
		uint8_t message_hash[32];
		memcpy(message_hash, Sha256.result(), 32);

		uint8_t signature[64];
		uECC_sign(ATTESTATION_KEY, message_hash, 32, signature, uECC_secp256r1());

		// convert signature to asn.1 format
		message[idx] = 0x30;
		idx++;
		int b1_idx = idx;
		idx++;
		uint8_t b1 = 68;
		message[idx] = 0x02;
		idx++;
		if (signature[0] > 0x7F)
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
		memcpy(message + idx, signature, 32); // copy r value
		idx += 32;
		message[idx] = 0x02;
		idx++;
		if (signature[32] > 0x7F)
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
		memcpy(message + idx, signature + 32, 32); // copy s value
		idx += 32;
		message[b1_idx] = b1;

		message[idx] = (SW_NO_ERROR >> 8) & 0xFF;
		idx++;
		message[idx] = SW_NO_ERROR & 0xFF;
		idx++;
		data_len = idx;
		// TODO: get user input here
		send_response();
	}
	else if (ins == U2F_AUTHENTICATE)
	{
		int req_data_len = (message[4] << 16) | (message[5] << 8) | message[6];
		// TODO: validate that req_data_len == 64

		int idx = 7;
		uint8_t challenge_param[32], application_param[32];
		memcpy(challenge_param, message + idx, 32);
		idx += 32;
		memcpy(application_param, message + idx, 32);
		idx += 32;

		uint8_t key_handle_len = message[idx];
		idx++;
		// TODO: validate that key_handle_len is 48
		uint8_t nonce[16];
		uint8_t mac[32];
		memcpy(nonce, message + idx, 16);
		idx += 16;
		memcpy(mac, message + idx, 32);

		Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(application_param[i]);
		}
		for (int i = 0; i < 16; i++)
		{
			Sha256.write(nonce[i]);
		}
		uint8_t private_key[32];
		memcpy(private_key, Sha256.resultHmac(), 32);

		Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(application_param[i]);
		}
		for (int i = 0; i < 32; i++)
		{
			Sha256.write(private_key[i]);
		}
		uint8_t computed_mac[32];
		memcpy(computed_mac, Sha256.resultHmac(), 32);

		if (memcmp(mac, computed_mac, 32) != 0)
		{
			data_len = 2;
			message[0] = (SW_WRONG_DATA >> 8) & 0xFF;
			message[1] = SW_WRONG_DATA & 0xFF;
		}
		if (p1 == 0x07) // check only
		{
			// already verified key handle above, so we just return success
			data_len = 2;
			message[0] = (SW_CONDITIONS_NOT_SATISFIED >> 8) & 0xFF;
			message[1] = SW_CONDITIONS_NOT_SATISFIED & 0xFF;
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
			for (int i = 0; i < 32; i++)
			{
				Sha256.write(application_param[i]);
			}
			Sha256.write(user_presence);
			for (int i = 0; i < 4; i++)
			{
				Sha256.write(counter_bytes[i]);
			}
			for (int i = 0; i < 32; i++)
			{
				Sha256.write(challenge_param[i]);
			}
			uint8_t message_hash[32];
			memcpy(message_hash, Sha256.result(), 32);

			uint8_t signature[64];
			uECC_sign(private_key, message_hash, 32, signature, uECC_secp256r1());

			// TODO: enforce user presence for 0x03
			int idx = 0;
			message[idx] = user_presence;
			idx++;
			memcpy(message + idx, counter_bytes, 4);
			idx += 4;

			// convert signature to asn.1 format
			message[idx] = 0x30;
			idx++;
			int b1_idx = idx;
			idx++;
			uint8_t b1 = 68;
			message[idx] = 0x02;
			idx++;
			if (signature[0] > 0x7F)
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
			memcpy(message + idx, signature, 32); // copy r value
			idx += 32;
			message[idx] = 0x02;
			idx++;
			if (signature[32] > 0x7F)
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
			memcpy(message + idx, signature + 32, 32); // copy s value
			idx += 32;
			message[b1_idx] = b1;

			message[idx] = (SW_NO_ERROR >> 8) & 0xFF;
			idx++;
			message[idx] = SW_NO_ERROR & 0xFF;
			idx++;
			data_len = idx;
			// counter_storage.write(counter + 1);
			send_response();
		}
	}
	else if (ins == U2F_VERSION)
	{
		Serial.println("unimplemented u2f command");
	}
	else
	{
		// TODO: send error
		Serial.println("ERROR: UNKNOWN U2F COMMAND");
	}
}

void handle()
{
	if (cmd == U2FHID_INIT)
	{
		handle_init();
	}
	else if (cmd == U2FHID_MSG)
	{
		handle_msg();
	}
	else if (cmd == U2FHID_PING || cmd == U2FHID_SYNC)
	{
		Serial.println("unimplemented command");
	}
	else
	{
		Serial.println("ERROR: UNKNOWN COMMAND");
		uint8_t packet[PACKET_SIZE];
		packet[0] = (cid >> 24) & 0xFF;
		packet[1] = (cid >> 16) & 0xFF;
		packet[2] = (cid >> 8) & 0xFF;
		packet[3] = cid & 0xFF;
		packet[4] = U2FHID_ERROR;
		packet[5] = (1 >> 8) & 0xFF;
		packet[6] = 1 & 0xFF;
		packet[7] = ERR_INVALID_CMD;
		usb_hid.sendReport(0, packet, PACKET_SIZE);
	}
}

void parse_packet(uint8_t const *packet)
{
	int packet_cid = (packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3];

	uint8_t cmd_or_seq = packet[4];
	bool is_init = cmd_or_seq >= 0x80; // if bit 7 is set, this is an init packet

	if (is_init)
	{
		if (!processing_message)
		{
			cid = packet_cid;
			cmd = cmd_or_seq;
			data_len = packet[5] << 8 | packet[6];
			memset(message, 0, sizeof(message));
			if (data_len <= PACKET_SIZE - 7)
			{
				// no continuation packets
				processing_message = false;
				data_cursor = data_len;
			}
			else
			{
				// will have continuation packets
				processing_message = true;
				data_cursor = PACKET_SIZE - 7;
			}
			memcpy(message, packet + 7, data_cursor);
			next_cont_packet = 0;
		}
		else
		{
			// TODO: send error response
			Serial.println("ERROR: BUSY");
		}
	}
	else
	{
		if (!processing_message) // ignore spurious continuation packets
		{
			Serial.println("ERROR: SPURIOUS CONTINUATION PACKET");
			return;
		}
		if (packet_cid != cid)
		{
			// TODO: send error
			Serial.println("ERROR: CID MISMATCH");
		}
		if (cmd_or_seq != next_cont_packet)
		{
			// TODO: send error
			Serial.println("ERROR: CONTINUATION PACKET OUT OF ORDER");
		}
		int bytes_needed = data_len - data_cursor;
		int data_end = min(PACKET_SIZE - 5, bytes_needed);
		memcpy(message + data_cursor, packet + 5, data_end);
		data_cursor += data_end;
		processing_message = data_cursor < data_len;
		if (processing_message)
		{
			next_cont_packet++;
		}
	}

	if (!processing_message)
	{
		// handle message
		handle();
	}
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void set_report_callback(uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize)
{
	parse_packet(buffer);
}
