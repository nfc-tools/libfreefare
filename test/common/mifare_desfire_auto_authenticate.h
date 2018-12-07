#ifndef _MIFARE_DESFIRE_AUTO_AUTHENTICATE_H
#define _MIFARE_DESFIRE_AUTO_AUTHENTICATE_H

extern uint8_t key_data_null[8];
extern uint8_t key_data_des[8];
extern uint8_t key_data_3des[16];
extern uint8_t key_data_aes[16];
extern uint8_t key_data_3k3des[24];
extern const uint8_t key_data_aes_version;

void		 mifare_desfire_auto_authenticate(FreefareTag tag, uint8_t key_no);

#endif
