#include <Arduino.h>
#include "u2f_hid.h"
#include "variables.h"
#include <Adafruit_TinyUSB.h>
#include <sha256.h>

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

void send_u2fhid_error(uint8_t error_code)
{
	cmd = U2FHID_ERROR;
	data_len = 1;
	message[0] = error_code;
	send_response();
}

void sha_write(uint8_t *data, int len)
{
	for (int i = 0; i < len; i++)
	{
		Sha256.write(data[i]);
	}
}

// formats signature and adds it to the message, starting at idx
int format_signature(int idx, uint8_t *signature)
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

void confirm_user_presence()
{
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
}