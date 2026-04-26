import skype_crypto from '../crypto/skype_crypto.js';
import common from '../crypto/common.js';
import TCPsender from './TCPsender.js';

function build_https_handshake() {
    const https_HandShake = Buffer.from([
        ...common.HTTPS_HSR_MAGIC,
        0x00, 0x2D, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x09, 0x00, 0x00, 0x64, 0x00, 0x00, 0x62, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x03, 0x00, 0x00, 0x06, 0x01, 0x00, 0x80, 0x07, 0x00, 0xC0, 0x03, 0x00, 0x80, 0x06,
        0x00, 0x40, 0x02, 0x00, 0x80, 0x04, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ]);

    for (let i = https_HandShake.length - 16; i < https_HandShake.length; i++) {
        https_HandShake[i] = Math.floor(Math.random() * 256);
    };
    
    return https_HandShake;
};

async function build_keyexchange(Skype_SuperNode_Config, time) {
    const server_seed = Math.floor(Math.random() * 0xFFFFFFFF) >>> 0;
    const keyexchange = Buffer.alloc(51);

    keyexchange.writeUInt32BE(server_seed, 0);
    keyexchange.writeUInt16BE(0x1234, 4);
    keyexchange.writeUInt32BE(0x00000001, 6);
    keyexchange.writeUInt32BE(0x00000003, 10);
    keyexchange[14] = 36 + 36 + 1;
    keyexchange[15] = 0x03;

    for (let i = 16; i < 51; i++) {
        keyexchange[i] = Math.floor(Math.random() * 256);
    };

    const RC4 = await skype_crypto.get_RC4_key(
        Skype_SuperNode_Config.keyserver_host,
        Skype_SuperNode_Config.keyserver_port,
        time,
        server_seed
    );

    if (!RC4 || RC4.length < 80) {
        logger.error(`[ERROR] ${time} RC4 Key is null`);
        return null;
    };

    const send_stream_key = Buffer.from(RC4.slice(0, 80));

    const header_stream = skype_crypto.create_RC4_stream(send_stream_key);
    const header = Buffer.from(keyexchange.slice(4, 14));
    const encrypted_header = header_stream.update(header);
    encrypted_header.copy(keyexchange, 4);

    const stream = skype_crypto.create_RC4_stream(send_stream_key);
    
    const tail = Buffer.from(keyexchange.slice(14));
    const encrypted_tail = stream.update(tail);
    encrypted_tail.copy(keyexchange, 14);

    return { keyexchange: keyexchange, server_seed: server_seed, send_stream_key: send_stream_key, stream: stream };
};

function build_client_accept(socket, stream, time, Client) {
    const client_ok = Buffer.alloc(8);

    client_ok[0] = 0x00;
    client_ok[1] = 0x26;
    client_ok[2] = 0xE1;
    client_ok[3] = 0x17;
    client_ok.writeUInt16BE(0xF801, 4);
    client_ok[6] = 0x73;
    client_ok[7] = 0x57;

    const encrypted = stream.update(client_ok);
    TCPsender.send(socket, encrypted, time, Client);
};

export default {
    build_https_handshake,
    build_keyexchange,
    build_client_accept
};