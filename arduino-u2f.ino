#include <Adafruit_TinyUSB.h>

uint8_t const desc_hid_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

// USB HID object.
// desc report, desc len, protocol, interval, use out endpoint
Adafruit_USBD_HID usb_hid(desc_hid_report, sizeof(desc_hid_report), HID_ITF_PROTOCOL_NONE, 2, true);

void setup()
{
	usb_hid.setReportCallback(NULL, set_report_callback);
	usb_hid.begin();

	Serial.begin(115200);

	while (!TinyUSBDevice.mounted())
	{
		delay(1);
	}

	Serial.println("finished setup");
}

void loop()
{
}

void write(uint8_t const *buffer)
{
	usb_hid.sendReport(0, buffer, 64);
}

void parse_packet(uint8_t const *report)
{
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void set_report_callback(uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize)
{
	Serial.println("set_report_callback");

	// echo back anything we received from host
	write(buffer);
}
