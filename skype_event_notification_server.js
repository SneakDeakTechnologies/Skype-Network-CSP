// Skype Network by NikDev!
import skype_crypto from './crypto/skype_crypto.js';
import UDPfunctions from './sender/UDPfunctions.js';
import UDPsender from './sender/UDPsender.js';
import logger from './logger/logger.js';
import common from './crypto/common.js';
import dgram from "dgram";
import 'dotenv/config';

const event_notification = dgram.createSocket('udp4');

const Skype_Event_Notification_Config = {
    host: process.env.skype_event_notification_host,
    port: parseInt(process.env.skype_event_notification_port),
    keyserver_host: process.env.skype_keyserver_host,
    keyserver_port: parseInt(process.env.skype_keyserver_port)
};

event_notification.on('message', async (message, rinfo) => {
    const string = message.toString('hex');
    const time = skype_crypto.get_time();
    const bytes = string.match(/.{1,2}/g)?.join(' ').toUpperCase();

    const Client = `${rinfo.address}:${rinfo.port}`;
    logger.print(`\n[DEBUG] ${time} Received ${message.length} bytes from ${Client}: ${bytes}`);

    const packetType = message[2];

    switch (packetType) {
        case 0x02:
            logger.print(`[DEBUG] ${time} Received PKT_TYPE_OBFSUK. Processing...`);
            const seed = skype_crypto.calculate_seed(message, rinfo, packetType, Skype_Event_Notification_Config.host, time);

            const RC4 = await skype_crypto.get_RC4_key(
                Skype_Event_Notification_Config.keyserver_host, 
                Skype_Event_Notification_Config.keyserver_port, 
                time,
                seed
            );
            
            const RC4_KEY = Buffer.alloc(80);
            RC4.copy(RC4_KEY, 0, 0, 80);

            const encrypted_body = message.subarray(8);
            skype_crypto.RC4(RC4_KEY, encrypted_body);
                        
            const decrypted_HEX = encrypted_body.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase();
            logger.print(`[DEBUG] ${time} Decrypted PKT_TYPE_OBFSUK body: ${decrypted_HEX}`);

            UDPsender.send(message, event_notification, rinfo, Client, time);
        break;
    };
});

event_notification.on('listening', () => {
    const address = event_notification.address();
    process.stdout.write('\x1B]0;Skype Event Notification Server\x07');
    logger.print(`Skype Event Notification Server is running on: udp://${address.address}:${address.port}`);
    logger.print(`Waiting for connections...`);
});

event_notification.bind(Skype_Event_Notification_Config.port, Skype_Event_Notification_Config.host);