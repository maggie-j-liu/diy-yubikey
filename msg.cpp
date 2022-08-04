#include "variables.h"
#include "u2f_hid.h"
#include "utils.h"
#include "keys.h"
#include <uECC.h>
#include <sha256.h>
#include "register.h"
#include "authenticate.h"

void handle_msg()
{
	uint8_t ins = message[1];
	if (ins == U2F_REGISTER)
	{
		handle_register();
		return;
	}
	else if (ins == U2F_AUTHENTICATE)
	{
		handle_authenticate();
		return;
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