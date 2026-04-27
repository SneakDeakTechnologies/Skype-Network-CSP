// Skype Network by NikDev!
import skype_crypto from './crypto/skype_crypto.js';
import UDPsender from './sender/UDPsender.js';
import logger from './logger/logger.js';
import dgram from "dgram";
import 'dotenv/config';

const keyserver = dgram.createSocket('udp4');

const Skype_KeyServer_Config = {
    host: process.env.skype_keyserver_host,
    port: parseInt(process.env.skype_keyserver_port)
};

keyserver.on('message', async (message, rinfo) => {
    const string = message.toString('hex');
    const time = skype_crypto.get_time();
    const bytes = string.match(/.{1,2}/g)?.join(' ').toUpperCase();

    const Client = `${rinfo.address}:${rinfo.port}`;
    logger.print(`\n[DEBUG] ${time} Received ${message.length} bytes from ${Client}: ${bytes}`);
    
    if (message.length === 4) {
        try {
            const RC4_KEY = Buffer.alloc(88);

            for (let i = 0; i < 20; i++) {
                message.copy(RC4_KEY, i * 4);
            };

            logger.print(`[DEBUG] ${time} Sent ${RC4_KEY.length} bytes to ${Client}: ${RC4_KEY.toString('hex').toUpperCase().match(/.{1,2}/g).join(' ')}`);
            await UDPsender.send(RC4_KEY, keyserver, rinfo, time);
        } catch (error) {
            logger.print(`[DEBUG] DLL execution failed: ${error.message}`);
        };
    };
});

keyserver.on('listening', () => {
    const address = keyserver.address();
    logger.print(`Skype Key Server is running on: udp://${address.address}:${address.port}`);
    logger.print(`Waiting for connections...`);
});

keyserver.bind(Skype_KeyServer_Config.port, Skype_KeyServer_Config.host);