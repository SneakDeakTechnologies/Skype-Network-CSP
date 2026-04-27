import skype_crypto from '../crypto/skype_crypto.js';
import logger from '../logger/logger.js';
import common from '../crypto/common.js';
import UDPsender from './UDPsender.js';

async function send_probe_ok(Skype_SuperNode_Config, supernode, remote, data, Client, requestID, time) {
    try {
        const probe_ok = Buffer.alloc(18);

        probe_ok[0] = data[0];
        probe_ok[1] = data[1];
        probe_ok[2] = common.PKT_TYPE_OBFSUK;

        const new_iv = Math.floor(Math.random() * 0xFFFFFFFF);
        probe_ok[3] = (new_iv >> 24) & 0xFF;
        probe_ok[4] = (new_iv >> 16) & 0xFF;
        probe_ok[5] = (new_iv >> 8) & 0xFF;
        probe_ok[6] = new_iv & 0xFF;

        probe_ok[11] = 0x04;
        probe_ok[12] = common.CMD_PROBE_OK * 8;
        probe_ok[13] = 0x00;

        const response_requestID = (requestID - 1) & 0xFFFF;
        probe_ok[14] = (response_requestID >> 8) & 0xFF;
        probe_ok[15] = response_requestID & 0xFF;

        probe_ok[16] = 0x41;
        probe_ok[17] = 0x00;

        const body = Buffer.alloc(7);
        probe_ok.copy(body, 0, 11, 18);
        const body_crc = skype_crypto.calculate_crc32(body, 0xFFFFFFFF);

        probe_ok[7] = (body_crc >> 24) & 0xFF;
        probe_ok[8] = (body_crc >> 16) & 0xFF;
        probe_ok[9] = (body_crc >> 8) & 0xFF;
        probe_ok[10] = body_crc & 0xFF;

        const to_crc = Buffer.alloc(12);

        const host_ip_bytes = Skype_SuperNode_Config.host.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            to_crc[i] = host_ip_bytes[3 - i];
        };

        const client_ip_bytes = remote.address.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            to_crc[4 + i] = client_ip_bytes[3 - i];
        };

        const transID_wire = ((data[0] << 8) | data[1]) & 0xFFFF;
        to_crc[8] = transID_wire & 0xFF;
        to_crc[9] = (transID_wire >> 8) & 0xFF;
        to_crc[10] = 0x00;
        to_crc[11] = 0x00;

        const crc_value = skype_crypto.calculate_crc32(to_crc, 0xFFFFFFFF);
        const seed = (crc_value ^ new_iv) >>> 0;

        const RC4 = await skype_crypto.get_RC4_key(
            Skype_SuperNode_Config.keyserver_host,
            Skype_SuperNode_Config.keyserver_port,
            time,
            seed
        );

        if (RC4 && RC4.length >= 80) {
            const RC4_KEY = Buffer.alloc(80);
            RC4.copy(RC4_KEY, 0, 0, 80);

            const body_to_encrypt = Buffer.alloc(7);
            probe_ok.copy(body_to_encrypt, 0, 11, 18);
            skype_crypto.RC4(RC4_KEY, body_to_encrypt);
            body_to_encrypt.copy(probe_ok, 11);
        };

        await UDPsender.send(probe_ok, supernode, remote, Client, time);
    } catch (error) {
        logger.print(`[ERROR] ${time} Failed to send CMD_PROBE_OK: ${error.message}`);
        throw error;
    };
};

async function send_nack_packet(server, remote, data, Client, time) {
    try {
        const nack = Buffer.alloc(11);

        nack[0] = data[0];
        nack[1] = data[1];
        nack[2] = 0x07;

        const ip_bytes = remote.address.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            nack[3 + i] = ip_bytes[i];
        };

        const challenge = Math.floor(Math.random() * 0xFFFFFFFF);

        const challenge_bytes = Buffer.alloc(4);
        challenge_bytes.writeUInt32BE(challenge, 0);

        challenge_bytes.copy(nack, 7, 0, 4);
        
        await UDPsender.send(nack, server, remote, Client, time);
    } catch (error) {
        logger.print(`[ERROR] ${time} Failed to send NACK: ${error.message}`);
        throw error;
    };
};

export default {
    send_probe_ok,
    send_nack_packet
};