void print_buffer(uint8_t const *buffer, int size);
int rng_func(uint8_t *dest, unsigned size);
void send_response();
void send_u2fhid_error(uint8_t error_code);
void sha_write(uint8_t *data, int len);
int format_signature(int idx, uint8_t *signature);
void confirm_user_presence();