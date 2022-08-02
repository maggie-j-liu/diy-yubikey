#include <Arduino.h>
#include "u2f_hid.h"
#include "variables.h"
#include <Adafruit_TinyUSB.h>

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