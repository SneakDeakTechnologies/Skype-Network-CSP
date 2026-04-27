// Skype Network by NikDev!
import skype_crypto from './crypto/skype_crypto.js';
import TCPfunctions from './sender/TCPfunctions.js';
import TCPsender from './sender/TCPsender.js';
import parser from './parser/parser.js';
import common from './crypto/common.js';
import logger from './logger/logger.js';
import mysql from 'mysql2';
import 'dotenv/config';
import net from 'net';
import fs from 'fs';

const MySQL = mysql.createPool({
    host: process.env.mysql_host,
    user: process.env.mysql_user,
    password: process.env.mysql_password,
    database: process.env.mysql_database
});

MySQL.getConnection((error, connection) => {
    if (error) {
        throw new Error(`[MySQL] MySQL Connection Error: ${error}`);
    } else {
        logger.print(`[MySQL] Successful MySQL Connection`);
        connection.release();
    };
});

const login = net.createServer((socket) => {
    const Client = `${socket.remoteAddress}:${socket.remotePort}`;
    const time = skype_crypto.get_time();

    logger.print(`\n[DEBUG] ${time} Work with Client: ${Client}`);

    socket.on('data', async (data) => {
        const time = skype_crypto.get_time();
        const hex = data.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase();

        logger.print(`\n[DEBUG] ${time} Received ${data.length} bytes from ${Client}: ${hex}`);

        if (data[0] === 0x16 && data[1] === 0x03 && data[2] === 0x01) {
            if (data.length === 5) {
                logger.print(`[DEBUG] ${time} Received Login HandShake. Processing...`);
                TCPfunctions.build_login_handshake(socket, time, Client);
            } else if (data[4] === 0xCD && data[5] === 0x41 && data[6] === 0x03) {
                logger.print(`[DEBUG] ${time} Received Login Auth. Processing...`);
                parser.parse_login_auth(data, time, fs.readFileSync('SSL/rsa_private.key'), fs.readFileSync('SSL/rsa_public.key'), socket, Client, MySQL);
            };
        };
    });
});

const Skype_Login_Server = {
    host: process.env.skype_login_host,
    port: parseInt(process.env.skype_login_port),
    keyserver_host: process.env.skype_keyserver_host,
    keyserver_port: parseInt(process.env.skype_keyserver_port)
};

login.listen(Skype_Login_Server.port, Skype_Login_Server.host, () => {
    process.stdout.write('\x1B]0;Skype Login Server\x07');
    logger.print(`Skype Login Server is running on: tcp://${Skype_Login_Server.host}:${Skype_Login_Server.port}`);
    logger.print(`Waiting for connections...\n`);
});