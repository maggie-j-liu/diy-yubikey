#include <Adafruit_TinyUSB.h>

#define PACKET_SIZE 64
uint8_t const desc_hid_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

// USB HID object.
// desc report, desc len, protocol, interval, use out endpoint
Adafruit_USBD_HID usb_hid(desc_hid_report, sizeof(desc_hid_report), HID_ITF_PROTOCOL_NONE, 2, true);

void print_buffer(uint8_t const *buffer, int size = PACKET_SIZE)
{
	for (int i = 0; i < size; i++)
	{
		Serial.print(buffer[i], HEX);
		Serial.print(" ");
	}
}

void setup()
{
	usb_hid.setReportCallback(NULL, set_report_callback);
	usb_hid.begin();

	Serial.begin(115200);
	while (!TinyUSBDevice.mounted())
	{
		delay(1);
	}
}

void loop()
{
}

void write(uint8_t const *buffer)
{
	usb_hid.sendReport(0, buffer, PACKET_SIZE);
}

bool processing_message = false;
int cid;
int data_len;
uint8_t cmd;
uint8_t message[7609]; // max message payload is 7609 bytes
int data_cursor;
uint8_t next_cont_packet = 0;

void parse_packet(uint8_t const *packet)
{
	int packet_cid;
	memcpy(&packet_cid, packet, sizeof(int));

	uint8_t cmd_or_seq = packet[4];
	Serial.print(cmd_or_seq, HEX);
	bool is_init = cmd_or_seq >= 0x80; // if bit 7 is set, this is an init packet

	if (is_init)
	{
		if (!processing_message)
		{
			cid = packet_cid;
			cmd = cmd_or_seq;
			data_len = packet[5] << 8 | packet[6];
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
			Serial.print("BUSY");
		}
		Serial.print("is init");
	}
	else
	{
		if (!processing_message) // ignore spurious continuation packets
		{
			Serial.print("SPURIOUS CONTINUATION PACKET");
			return;
		}
		if (packet_cid != cid)
		{
			// TODO: send error
			Serial.print("CID MISMATCH");
		}
		if (cmd_or_seq != next_cont_packet)
		{
			// TODO: send error
			Serial.print("CONTINUATION PACKET OUT OF ORDER");
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
		Serial.print("is cnt");
	}
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void set_report_callback(uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize)
{
	parse_packet(buffer);

	// echo back anything we received from host
	// write(buffer);
}
