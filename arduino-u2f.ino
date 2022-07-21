#include <Adafruit_TinyUSB.h>
#include "u2f_hid.h"
#include <uECC.h>
#include "keys.h"
#include <sha256.h>

uint8_t const desc_hid_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

// USB HID object.
// desc report, desc len, protocol, interval, use out endpoint
Adafruit_USBD_HID usb_hid(desc_hid_report, sizeof(desc_hid_report), HID_ITF_PROTOCOL_NONE, 1, true);

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
	randomSeed(analogRead(0));
	usb_hid.setReportCallback(NULL, set_report_callback);
	usb_hid.begin();

	Serial.begin(115200);
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

void send_response(bool print = false)
{
	uint8_t packet[PACKET_SIZE];
	memcpy(packet, &cid, 4);
	packet[4] = cmd;
	packet[5] = (data_len >> 8) & 0xFF;
	packet[6] = data_len & 0xFF;
	int included = min(PACKET_SIZE - 7, data_len);
	memcpy(packet + 7, message, included);
	next_cont_packet = 0;
	usb_hid.sendReport(0, packet, PACKET_SIZE);
	if (print)
	{
		Serial.print(packet[5], HEX);
		Serial.print(" ");
		Serial.println(packet[6], HEX);
	}

	while (included < data_len)
	{
		while (!tud_hid_ready())
		{
			delay(1);
			tud_task(); // important! otherwise tud_hid_ready will always be false
		}
		memset(packet, 0, PACKET_SIZE);
		memcpy(packet, &cid, 4);
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
	Serial.println("handling init");
	int new_cid = 1;
	data_len = 17;
	// since we are using message as the response buffer, the nonce doesn't change
	memcpy(message + 8, &new_cid, 4);
	message[12] = U2FHID_IF_VERSION; // protocol version
	message[13] = 1;				 // major version
	message[14] = 0;				 // minor version
	message[15] = 1;				 // device version
	message[16] = 0;				 // capabilities
	send_response();
}

void handle_msg()
{
	Serial.println("handling msg");
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
		uint8_t *hash;
		uint8_t nonce[16];
		for (int i = 0; i < 16; i++)
		{
			nonce[i] = random(256) & 0xFF;
		}
		Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
		Sha256.print((char *)application_param);
		Sha256.print((char *)nonce);
		uint8_t *private_key = Sha256.resultHmac();
		int computed = uECC_compute_public_key(private_key, public_key + 1, uECC_secp256r1());

		Sha256.initHmac(MASTER_KEY, sizeof(MASTER_KEY));
		Sha256.print((char *)application_param);
		Sha256.print((char *)private_key);
		uint8_t *mac = Sha256.resultHmac();

		int idx = 0;
		message[idx] = 0x05;
		idx++;
		memcpy(message + idx, public_key, 65);
		idx += 65;
		message[idx] = 16 + 32; // length of key handle
		Serial.print("length of key handle: ");
		Serial.println(message[idx], HEX);
		idx++;
		memcpy(message + idx, nonce, 16);
		idx += 16;
		memcpy(message + idx, mac, 32);
		idx += 32;
		memcpy(message + idx, ATTESTATION_CERT, 319);
		idx += 319;

		Sha256.init();
		Sha256.print(0x00);
		Sha256.print((char *)application_param);
		Sha256.print((char *)challenge_param);
		Sha256.print((char *)nonce);
		Sha256.print((char *)mac);
		Sha256.print((char *)public_key);
		uint8_t *message_hash = Sha256.result();

		uint8_t signature[64];
		uECC_sign(private_key, message_hash, 32, signature, uECC_secp256r1());

		// convert signature to asn.1 format
		Serial.print("sig start: ");
		Serial.println(idx);
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
		Serial.print("sig end: ");
		Serial.println(idx);
		message[idx] = (SW_NO_ERROR >> 8) & 0xFF;
		idx++;
		message[idx] = SW_NO_ERROR & 0xFF;
		idx++;
		data_len = idx;
		Serial.print("data len: ");
		Serial.println(data_len);
		// TODO: get user input here
		send_response(true);
	}
	else if (ins == U2F_AUTHENTICATE || ins == U2F_VERSION)
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
		memcpy(packet, &cid, 4);
		packet[4] = U2FHID_ERROR;
		packet[5] = (1 >> 8) & 0xFF;
		packet[6] = 1 & 0xFF;
		packet[7] = ERR_INVALID_CMD;
		usb_hid.sendReport(0, packet, PACKET_SIZE);
	}
}

void parse_packet(uint8_t const *packet)
{
	int packet_cid;
	memcpy(&packet_cid, packet, sizeof(int));

	uint8_t cmd_or_seq = packet[4];
	Serial.println(cmd_or_seq, HEX);
	bool is_init = cmd_or_seq >= 0x80; // if bit 7 is set, this is an init packet

	if (is_init)
	{
		if (!processing_message)
		{
			cid = packet_cid;
			cmd = cmd_or_seq;
			if (cmd == U2FHID_MSG)
			{
				Serial.println("message packet recv");
				print_buffer(packet);
			}
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
		Serial.println("is init");
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
		Serial.println("is cnt");
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
	// print_buffer(buffer);
	parse_packet(buffer);

	// echo back anything we received from host

	// Serial.println();
	// Serial.println(write(buffer));
	// while (!tud_hid_ready())
	// {
	// 	Serial.print("delay");
	// 	delay(1);
	// 	tud_task();
	// }
	// Serial.println(tud_hid_ready());
	// // Serial.print("written 1");
	// Serial.println(write(buffer));
}
