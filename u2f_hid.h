#define PACKET_SIZE 64			 // Default size of raw HID report
#define CID_BROADCAST 0xffffffff // Broadcast channel id

#define TYPE_MASK 0x80 // Frame type mask
#define TYPE_INIT 0x80 // Initial frame identifier
#define TYPE_CONT 0x00 // Continuation frame identifier

#define U2FHID_PING (TYPE_INIT | 0x01)	// 129
#define U2FHID_MSG (TYPE_INIT | 0x03)	// 131
#define U2FHID_LOCK (TYPE_INIT | 0x04)	// 132
#define U2FHID_INIT (TYPE_INIT | 0x06)	// 134
#define U2FHID_WINK (TYPE_INIT | 0x08)	// 136
#define U2FHID_SYNC (TYPE_INIT | 0x3c)	// 188
#define U2FHID_ERROR (TYPE_INIT | 0x3f) // 191

#define U2FHID_IF_VERSION 2 // Current interface implementation version
#define CAPFLAG_WINK 0x01	// Device supports WINK command
#define CAPFLAG_LOCK 0x02	// Device supports LOCK command

#define U2F_REGISTER 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION 0x03

#define ERR_NONE 0x00
#define ERR_INVALID_CMD 0x01
#define ERR_INVALID_PAR 0x02
#define ERR_INVALID_LEN 0x03
#define ERR_INVALID_SEQ 0x04
#define ERR_MSG_TIMEOUT 0x05
#define ERR_CHANNEL_BUSY 0x06
#define ERR_LOCK_REQUIRED 0x0a
#define ERR_SYNC_FAIL 0x0b
#define ERR_OTHER 0x7f

#define SW_NO_ERROR 0x9000
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA 0x6A80
#define SW_WRONG_LENGTH 0x6700
#define SW_CLA_NOT_SUPPORTED 0x6D00