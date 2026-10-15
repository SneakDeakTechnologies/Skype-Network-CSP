// proto/common/common.h
#pragma once

#include <cstdint>
#include <vector>
#include <string>

#define PKT_TYPE_CTRL 0x03

#define CMD_CLIENT    0xF201
#define CMD_NETSTATS  0x59
#define CMD_SLOTINFO  0x06

#define OBJ_ID_STACKVER	   0x0B
#define OBJ_ID_STACKTS	   0x0C
#define OBJ_ID_PEERLPORT   0x10
#define OBJ_ID_PUBNETADDR  0x11
#define OBJ_ID_NODE		   0x21
#define OBJ_ID_NBCONNECTED 0x09
#define OBJ_ID_USERNAME		0x04
#define  OBJ_ID_USERPASS	0x05
#define  OBJ_ID_MODULUS		0x21
#define	 OBJ_FAMILY_NBR		0x00
#define	 OBJ_FAMILY_TABLE	0x01
#define	 OBJ_FAMILY_NETADDR	0x02
#define	 OBJ_FAMILY_STRING	0x03
#define	 OBJ_FAMILY_BLOB	0x04
#define  OBJ_ID_CIPHERDLOGD 0x24
#define	 OBJ_FAMILY_OBJLIST	0x05
#define  OBJ_FAMILY_INTLIST	0x06
#define  OBJ_ID_LOGINANSWER 0x01
#define  OBJ_ID_PLATFORM    0x31
#define  OBJ_ID_MISCD       0x33
#define  OBJ_ID_ESAUTHANSWR 0x0A
#define  OBJ_ID_VERSION     0x0D
#define  OBJ_ID_STACKVER    0x0B
#define	 OBJ_ID_LDUSER		0x00
#define	 OBJ_ID_LDEXPIRY	0x04
#define	 OBJ_ID_LDMODULUS	0x01
