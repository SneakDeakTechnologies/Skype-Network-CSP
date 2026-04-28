import skype_crypto from '../crypto/skype_crypto.js';
import TCPsender from '../sender/TCPsender.js';
import common from '../crypto/common.js';
import crypto from 'crypto';

function build_https_handshake(socket, time, Client) {
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

    TCPsender.send(socket, https_HandShake, time, Client);
};

async function build_keyexchange(Skype_SuperNode_Config, socket, time, Client) {
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

    TCPsender.send(socket, keyexchange, time, Client);
    return { server_seed: server_seed, send_stream_key: send_stream_key, stream: stream };
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

function build_handShake_response(socket, time, Client) {
    const handShake = Buffer.from([...common.HTTPS_HSR_MAGIC, 0x00, 0x00]);
    TCPsender.send(socket, handShake, time, Client);
};

function build_login_ok(username, aes_key, public_key, time, socket, Client) {
    const LOGIN_OK_VAR = skype_crypto.write_int(common.LOGIN_OK);
    
    let login_ok_header = Buffer.alloc(0);
    login_ok_header = Buffer.concat([login_ok_header, Buffer.from([0x41, 0x02])]);
    login_ok_header = Buffer.concat([login_ok_header, Buffer.from([0x00, 0x01])]);
    login_ok_header = Buffer.concat([login_ok_header, LOGIN_OK_VAR]);
    login_ok_header = Buffer.concat([login_ok_header, Buffer.from([0x04, 0x24])]);

    const encrypted = skype_crypto.aes_ctr_encrypt(login_ok_header, aes_key);
    
    const login_ok_packet = Buffer.alloc(5 + encrypted.length);
    login_ok_packet[0] = 0x17;
    login_ok_packet[1] = 0x03;
    login_ok_packet[2] = 0x01;
    login_ok_packet.writeUInt16BE(encrypted.length, 3);
    encrypted.copy(login_ok_packet, 5);

    TCPsender.send(socket, login_ok_packet, time, Client);
};

function build_slotinfo_response(socket, time, Client, stream, value, slotId) {
    const slotinfo_response = Buffer.alloc(0);
    let body = Buffer.alloc(0);

    body = Buffer.concat([body, Buffer.from([0x00, 0x00])]);
    body = Buffer.concat([body, skype_crypto.write_int(slotId)]);
    body = Buffer.concat([body, Buffer.from([0x00, 0x07])]);
    body = Buffer.concat([body, skype_crypto.write_int(1)]);
    body = Buffer.concat([body, Buffer.from([0x02, 0x03])]); 
    body = Buffer.concat([body, Buffer.from([26, 30, 222, 230])]);

    const port = Buffer.alloc(2);
    port.writeUInt16BE(33033);
    body = Buffer.concat([body, port]);

    const size = 2 + 2 + 1 + 1 + body.length;
    let packet = skype_crypto.write_int(size);
    packet = Buffer.concat([packet, skype_crypto.write_int(0x43)]);
    packet = Buffer.concat([packet, Buffer.from([0x00, 0x00])]);
    packet = Buffer.concat([packet, Buffer.from([0x41])]);
    packet = Buffer.concat([packet, skype_crypto.write_int(3)]);
    packet = Buffer.concat([packet, body]);

    const encrypted = stream.update(packet);
    TCPsender.send(socket, encrypted, time, Client);
};

export default {
    build_https_handshake,
    build_keyexchange,
    build_client_accept,
    build_handShake_response,
    build_login_ok,
    build_slotinfo_response
};