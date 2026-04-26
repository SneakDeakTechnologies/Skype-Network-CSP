const LOGIN_OK = 4200;
const ESAUTH_OK = 0xBB8; 

const HTTPS_HSR_MAGIC = [0x16, 0x03, 0x01];

const PKT_TYPE_OBFSUK = 0x02;
const PKT_TYPE_RESEND = 0x03;
const PKT_TYPE_NACK = 0x07;

const CMD_PROBE_OK = 0x1C;
const CMD_PROBE_REFUSED = 0x1D;
const CMD_CLIENT_OK = 0x1F;
const CMD_CLIENT_REFUSED = 0x20;

export default {
    LOGIN_OK,
    ESAUTH_OK,
    HTTPS_HSR_MAGIC,
    PKT_TYPE_OBFSUK,
    PKT_TYPE_RESEND,
    PKT_TYPE_NACK,
    CMD_PROBE_OK,
    CMD_PROBE_REFUSED,
    CMD_CLIENT_OK,
    CMD_CLIENT_REFUSED,
};