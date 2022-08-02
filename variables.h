#include <Adafruit_TinyUSB.h>
#include <FlashStorage.h>
#include <Adafruit_NeoPixel.h>
#include <Adafruit_FreeTouch.h>

extern Adafruit_USBD_HID usb_hid;
extern FlashStorageClass<int> counter_storage;
extern Adafruit_NeoPixel strip;
extern Adafruit_FreeTouch touch_pad_1;
extern Adafruit_FreeTouch touch_pad_2;

extern bool processing_message;
extern int cid;
extern int data_len;
extern uint8_t cmd;
extern uint8_t message[7609]; // max message payload is 7609 bytes
extern int data_cursor;
extern uint8_t next_cont_packet;