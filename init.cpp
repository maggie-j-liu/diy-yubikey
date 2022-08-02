#include "variables.h"
#include "u2f_hid.h"
#include "utils.h"

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
	return;
}