// Skype Network by NikDev!
import skype_crypto from './crypto/skype_crypto.js';
import TCPfunctions from './sender/TCPfunctions.js';
import TCPsender from './sender/TCPsender.js';
import common from './crypto/common.js';
import logger from './logger/logger.js';
import 'dotenv/config';
import net from 'net';

let stream;
let server_seed;
let client_seed;
let send_stream_key;
let recv_stream_key;

const supernode = net.createServer((socket) => {
    const Client = `${socket.remoteAddress}:${socket.remotePort}`;
    const time = skype_crypto.get_time();

    logger.print(`\n[DEBUG] ${time} Work with Client: ${Client}`);

    socket.on('data', async (data) => {
        const time = skype_crypto.get_time();
        const hex = data.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase();
        
        logger.print(`\n[DEBUG] ${time} Received ${data.length} bytes from ${Client}: ${hex}`);

        if (data.length === 72 && data[0] === 0x80 && data[1] === 0x46 && data[2] === 0x01) {
            logger.print(`[DEBUG] ${time} Received Skype HTTPS HandShake. Processing...`);
            
            const https_HandShake = TCPfunctions.build_https_handshake();
            TCPsender.send(socket, https_HandShake, time, Client);
        } else if (data.length === 51 || data.length === 14) {
            logger.print(`[DEBUG] ${time} Received Key-Exchange. Processing...`);
            client_seed = data.readInt32BE(0) >>> 0;

            const RC4 = await skype_crypto.get_RC4_key(
                Skype_SuperNode_Config.keyserver_host, 
                Skype_SuperNode_Config.keyserver_port, 
                time,
                client_seed
            );
        
            if (!RC4 || RC4.length < 88) {
                logger.error(`[ERROR] ${time} RC4 Key is null`);
                return socket.close();
            };

            const RC4_KEY = Buffer.alloc(80);
            RC4.copy(RC4_KEY, 0, 0, 80);

            recv_stream_key = skype_crypto.create_RC4_stream(RC4_KEY);

            const ctrl_body = data.slice(14);
            recv_stream_key.update(ctrl_body);

            const keyexchange_packet = await TCPfunctions.build_keyexchange(Skype_SuperNode_Config, time);

            const keyexchange = keyexchange_packet.keyexchange;
            server_seed = keyexchange_packet.server_seed;
            send_stream_key = keyexchange_packet.send_stream_key;
            stream = keyexchange_packet.stream;

            TCPsender.send(socket, keyexchange, time, Client);
        } else if (data.length === 31) {
            logger.print(`[DEBUG] ${time} Received Client Accept. Processing...`);  
            
            const encrypted_data = Buffer.from(data);
            const decrypted = recv_stream_key.update(encrypted_data);

            /* const decrypted_HEX = decrypted.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase();
            logger.print(`[DEBUG] ${time} Decrypted Client Accept: ${decrypted_HEX}`); */

            if (decrypted[4] === 0xF2 && decrypted[5] === 0x01) {
                logger.print(`[DEBUG] ${time} Received CMD_CLIENT_CLIENT. Processing...`);
                let offset = 10;

                const family_nodeid = decrypted[offset];
                const id_nodeid = decrypted[offset + 1];
                offset += 2;

                const nodeid_raw = decrypted.slice(offset, offset + 8);
                const nodeid = Buffer.from(nodeid_raw).reverse();
                offset += 8;

                const family_port = decrypted[offset];
                const id_port = decrypted[offset + 1];
                offset += 2;

                const port = skype_crypto.read_int(decrypted, offset);
                const listeningPort = port.value;
                offset += port.size;

                logger.print(`[DEBUG] ${time} NodeID: ${nodeid.toString('hex').toUpperCase()}`);
                logger.print(`[DEBUG] ${time} Listening Port: ${listeningPort}`);

                TCPfunctions.build_client_accept(socket, stream, time, Client);
            };
        };
    });
});

const Skype_SuperNode_Config = {
    host: process.env.skype_tcp_supernode_host,
    port: process.env.skype_tcp_supernode_port,
    keyserver_host: process.env.skype_keyserver_host,
    keyserver_port: process.env.skype_keyserver_port
};

supernode.listen(Skype_SuperNode_Config.port, Skype_SuperNode_Config.host, () => {
    process.stdout.write('\x1B]0;Skype SuperNode Server\x07');
    logger.print(`Skype SuperNode Server is running on: tcp://${Skype_SuperNode_Config.host}:${Skype_SuperNode_Config.port}`);
    logger.print(`Waiting for connections...`);
});