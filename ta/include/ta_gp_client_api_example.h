#ifndef TA_GP_CLIENT_API_EXAMPLE_H
#define TA_GP_CLIENT_API_EXAMPLE_H

/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_GP_CLIENT_API_EXAMPLE_UUID { 0xf894e6e0, 0x1215, 0x11e6, \
		{ 0x92, 0x81, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

/* The TAFs ID implemented in this TA */
#define CMD_CREATE_KEY 0
#define CMD_ENCRYPT_INIT 1
#define CMD_ENCRYPT_UPDATE 2
#define CMD_ENCRYPT_FINAL 3
#define CMD_DIGEST_INIT 4
#define CMD_DIGEST_UPDATE 5
#define CMD_DIGEST_FINAL 6
#define CMD_ENCRYPT 7
#define CMD_DIGEST 8

#endif /*TA_GP_CLIENT_API_EXAMPLE_H*/
