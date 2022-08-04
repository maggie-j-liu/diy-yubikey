#include <Adafruit_TinyUSB.h>
#include "u2f_hid.h"
#include <uECC.h>
#include "keys.h"
#include <FlashStorage.h>
#include <Adafruit_NeoPixel.h>
#include <Adafruit_FreeTouch.h>
#include "utils.h"
#include "variables.h"
#include "init.h"
#include "msg.h"

uint8_t const desc_hid_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

// USB HID object.
// desc report, desc len, protocol, interval, use out endpoint
Adafruit_USBD_HID usb_hid(desc_hid_report, sizeof(desc_hid_report), HID_ITF_PROTOCOL_NONE, 1, true);

FlashStorage(counter_storage, int);

// Create the neopixel strip with the built in definitions NUM_NEOPIXEL and PIN_NEOPIXEL
Adafruit_NeoPixel strip = Adafruit_NeoPixel(NUM_NEOPIXEL, PIN_NEOPIXEL, NEO_GRB + NEO_KHZ800);

// Create the two touch pads on pins 1 and 2:
Adafruit_FreeTouch touch_pad_1 = Adafruit_FreeTouch(1, OVERSAMPLE_4, RESISTOR_50K, FREQ_MODE_NONE);
Adafruit_FreeTouch touch_pad_2 = Adafruit_FreeTouch(2, OVERSAMPLE_4, RESISTOR_50K, FREQ_MODE_NONE);

bool processing_message = false;
int cid;
int data_len;
uint8_t cmd;
uint8_t message[7609]; // max message payload is 7609 bytes
int data_cursor;
uint8_t next_cont_packet = 0;

void setup()
{
	Serial.begin(115200);

	strip.begin();
	strip.setBrightness(10);
	for (int i = 0; i < strip.numPixels(); i++)
	{
		strip.setPixelColor(i, strip.Color(255, 0, 0));
	}
	strip.show();

	randomSeed(analogRead(0));
	usb_hid.setReportCallback(NULL, set_report_callback);
	usb_hid.begin();

	touch_pad_1.begin();
	touch_pad_2.begin();

	while (!TinyUSBDevice.mounted())
	{
		delay(1);
	}
	uECC_set_rng(rng_func);
}

void loop()
{
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
	else if (cmd == U2FHID_PING)
	{
		send_response();
	}
	else
	{
		// Serial.println("ERROR: UNKNOWN COMMAND");
		send_u2fhid_error(ERR_INVALID_CMD);
		return;
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
			// abort current transaction
			if (cmd_or_seq == U2FHID_SYNC)
			{
				processing_message = false;
				return;
			}
			// send error response
			Serial.println("ERROR: BUSY");
			send_u2fhid_error(ERR_CHANNEL_BUSY);
			return;
		}
	}
	else
	{
		if (!processing_message) // ignore spurious continuation packets
		{
			Serial.println("ERROR: SPURIOUS CONTINUATION PACKET");
			send_u2fhid_error(ERR_INVALID_SEQ);
			return;
		}
		if (packet_cid != cid)
		{
			Serial.println("ERROR: CID MISMATCH");
			send_u2fhid_error(ERR_CHANNEL_BUSY);
			return;
		}
		if (cmd_or_seq != next_cont_packet)
		{
			Serial.println("ERROR: CONTINUATION PACKET OUT OF ORDER");
			send_u2fhid_error(ERR_INVALID_SEQ);
			return;
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
