// Skype Network by NikDev!
import skype_crypto from './crypto/skype_crypto.js';
import UDPfunctions from './sender/UDPfunctions.js';
import UDPsender from './sender/UDPsender.js';
import logger from './logger/logger.js';
import common from './crypto/common.js';
import dgram from "dgram";
import 'dotenv/config';

const supernode = dgram.createSocket('udp4');

const Skype_SuperNode_Config = {
    host: process.env.skype_udp_supernode_host,
    port: parseInt(process.env.skype_udp_supernode_port),
    keyserver_host: process.env.skype_keyserver_host,
    keyserver_port: parseInt(process.env.skype_keyserver_port)
};

supernode.on('message', async (message, rinfo) => {
    const string = message.toString('hex');
    const time = skype_crypto.get_time();
    const bytes = string.match(/.{1,2}/g)?.join(' ').toUpperCase();

    const Client = `${rinfo.address}:${rinfo.port}`;
    logger.print(`\n[DEBUG] ${time} Received ${message.length} bytes from ${Client}: ${bytes}`);

    const packetType = message[2];

    switch (packetType) {
        case 0x02:
            logger.print(`[DEBUG] ${time} Received PKT_TYPE_OBFSUK. Processing...`);
            UDPfunctions.send_nack_packet(supernode, rinfo, message, Client, time);
        break;

        case 0x03:
            logger.print(`[DEBUG] ${time} Received PKT_TYPE_RESEND. Processing...`);
            const seed = skype_crypto.calculate_seed(message, rinfo, packetType, Skype_SuperNode_Config.host, time);

            const RC4 = await skype_crypto.get_RC4_key(
                Skype_SuperNode_Config.keyserver_host, 
                Skype_SuperNode_Config.keyserver_port, 
                time,
                seed
            );
            
            const RC4_KEY = Buffer.alloc(80);
            RC4.copy(RC4_KEY, 0, 0, 80);
            
            // const rc4_key_hex = RC4_KEY.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase();
            
            const encrypted_body = Buffer.alloc(message.length - 16);
            message.copy(encrypted_body, 0, 16, message.length);
            
            skype_crypto.RC4(RC4_KEY, encrypted_body);
            
            const decrypted_HEX = encrypted_body.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase();
            logger.print(`[DEBUG] ${time} Decrypted PKT_TYPE_RESEND body: ${decrypted_HEX}`);

            const header_crc_net = message.readUInt32BE(12);
            const header_crc_host = skype_crypto.networkToHostOrder(header_crc_net);

            const calculated_crc32_le = skype_crypto.calculate_crc32(encrypted_body, 0xFFFFFFFF);
            const calculated_crc32 = skype_crypto.hostToNetworkOrder(calculated_crc32_le);

            if (calculated_crc32 === header_crc_host) {
                logger.print(`[DEBUG] ${time} CRC32 Match!`);

                if (encrypted_body[0] === 0x04 && encrypted_body[1] === 0xDA && encrypted_body[2] === 0x01) {
                    logger.print(`[DEBUG] ${time} Received CMD_PROBE. Processing..`);
                    
                    const RequestID = (encrypted_body[5] << 8) | encrypted_body[6];
                    await UDPfunctions.send_probe_ok(Skype_SuperNode_Config, supernode, rinfo, message, Client, RequestID, time);
                };
            } else {
                logger.print(`[DEBUG] ${time} CRC32 Mismatch!`);
            };
        break;
    };
});

supernode.on('listening', () => {
    const address = supernode.address();
    process.stdout.write('\x1B]0;Skype UDP SuperNode Server\x07');
    logger.print(`Skype UDP SuperNode Server is running on: udp://${address.address}:${address.port}`);
    logger.print(`Waiting for connections...`);
});

supernode.bind(Skype_SuperNode_Config.port, Skype_SuperNode_Config.host);