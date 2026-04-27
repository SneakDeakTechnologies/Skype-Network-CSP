import skype_crypto from "../crypto/skype_crypto.js";
import TCPfunctions from "../sender/TCPfunctions.js";
import logger from "../logger/logger.js";
import crypto from 'crypto';
import net from 'net';

function parse_auth_credentials(decrypted_blob, socket, time) {
    let offset = 0;
    let data = decrypted_blob;

    if (data.length > 2 && data[data.length - 2] === 0x01) {
        data = decrypted_blob.slice(0, -2);
    };

    const idx_login = decrypted_blob.indexOf(Buffer.from([0x03, 0x04]));

    if (idx_login === -1) {
        logger.print(`[DEBUG] ${time} Login field not found. Skipping...`);
        return socket.end();
    };

    let pos = idx_login + 2;
    let login_end = decrypted_blob.indexOf(0x00, pos);

    const username = decrypted_blob.slice(pos, login_end).toString('utf8');
    const idx_cred = decrypted_blob.indexOf(Buffer.from([0x04, 0x05, 0x10]));

    if (idx_cred === -1) {
        logger.print(`[DEBUG] ${time} Credentials field not found. Skipping...`);
        return socket.end();
    };

    const cred_start = idx_cred + 3;
    const credentials = decrypted_blob.slice(cred_start, cred_start + 16);

    let modulus = null;
    let idx_modulus = data.indexOf(Buffer.from([0x04, 0x0E]));

    if (idx_modulus === -1) {
        idx_modulus = data.indexOf(Buffer.from([0x04, 0x21]));
    };
    
    if (idx_modulus !== -1) {
        let len_pos = idx_modulus + 2;
        let modulus_len = data[len_pos];
        len_pos++;
        
        if (modulus_len > 0x80) {
            modulus_len = ((modulus_len & 0x7F) << 7) | data[len_pos];
            len_pos++;
        };
        
        modulus = data.slice(len_pos, len_pos + modulus_len);
    };

    return { username: username, credentials: credentials, modulus: modulus };
};

function parse_login_auth(data, time, private_key, public_key, socket, Client, MySQL) {
    let offset = 5;

    const RAW_PARAMS = data[offset++];
    logger.print(`[DEBUG] ${time} RAW_PARAMS: 0x${RAW_PARAMS.toString(16).toUpperCase()}`);

    if (RAW_PARAMS !== 0x41) {
        logger.print(`[DEBUG] ${time} Unknown RAW_PARAMS. Skipping...`);
        return;
    };

    const NbObj = data[offset++];
    logger.print(`[DEBUG] ${time} NbObj: 0x${NbObj.toString(16).toUpperCase()}`);

    const family1 = data[offset++];
    logger.print(`[DEBUG] ${time} OBJ_FAMILY_NBR: 0x${family1.toString(16).toUpperCase()}`);

    const id1 = data[offset++];
    logger.print(`[DEBUG] ${time} OBJ_ID_2000: 0x${id1.toString(16).toUpperCase()}`);

    if (family1 !== 0x00 || id1 !== 0x09) {
        logger.print(`[DEBUG] ${time} Invalid OBJ_ID_2000. Skipping...`);
        return;
    };

    const val = skype_crypto.read_int(data, offset);
    offset += val.size;

    logger.print(`[DEBUG] ${time} All service bytes is ok. Authorizing...`);

    const family2 = data[offset++];
    logger.print(`[DEBUG] ${time} OBJ_FAMILY_BLOB: 0x${family2.toString(16).toUpperCase()}`);

    const id2 = data[offset++];
    logger.print(`[DEBUG] ${time} OBJ_ID_SK: 0x${id2.toString(16).toUpperCase()}`);

    if (family2 !== 0x04 || id2 !== 0x08) {
        logger.print(`[DEBUG] ${time} OBJ_ID_SK not found. Skipping`);
        return;
    };

    const len = skype_crypto.read_int(data, offset);
    offset += len.size;

    const rsa_blob = data.slice(offset, offset + len.value);
    offset += len.value;

    const sessionKey = crypto.privateDecrypt(
        {
            key: private_key,
            padding: crypto.constants.RSA_NO_PADDING
        },
        rsa_blob
    );

    // logger.print(`[DEBUG] ${time} Decrypted SessionKey: ${sessionKey.toString('hex').match(/.{1,2}/g).join(' ').toUpperCase()}`);

    const aes_key = skype_crypto.specialSHA(sessionKey);
    // logger.print(`[DEBUG] ${time} AES-256 key: ${aes_key.toString('hex').match(/.{1,2}/g).join(' ').toUpperCase()}`);

    const encrypted_start = offset;
    const magic_enc = data.toString('ascii', encrypted_start, encrypted_start + 4);
    
    const enc_response_len = data.readUInt16BE(encrypted_start + 4);
    const encrypted_data = data.slice(encrypted_start + 8, encrypted_start + 8 + enc_response_len - 2);

    const decrypted_blob = skype_crypto.aes_ctr_decrypt(encrypted_data, aes_key, false);
    // logger.print(`[DEBUG] ${time} Decrypted Auth Blob:\n${decrypted_blob.slice(0, -2).toString('hex').match(/.{1,2}/g).join(' ').toUpperCase()}`);

    const user_data = parse_auth_credentials(decrypted_blob, socket, time);
    const username = user_data.username;
    const credentials = user_data.credentials;
    const modulus = user_data.modulus;

    if (!username) {
        logger.print(`[DEBUG] ${time} Login not found. Skipping...`);
        return socket.end();
    } else if (!credentials) {
        logger.print(`[DEBUG] ${time} Credentials not found. Skipping...`);
        return socket.end();
    };

    logger.print(`[DEBUG] ${time} Login attempt from username: ${username}. Processing...`);

    MySQL.query(
        'SELECT * FROM users WHERE username = ?',
        [username],
        (error, users) => {
            if (error) {
                return logger.error(`[ERROR] ${time} MySQL Error: ${error}. Skipping...`);
            };

            if (!users || users.length === 0) {
                return logger.print(`[DEBUG] ${time} User ${username} not found. Skipping...`);
            };

            const user = users[0];
            const valid_credentials = user.credentials;

            if (credentials.toString('hex') === valid_credentials) {
                logger.print(`[DEBUG] ${time} Successful login from username: ${username}. Sending LOGIN_OK...`);
                TCPfunctions.build_login_ok(username, aes_key, public_key, time, socket, Client);
            };
        }
    );
};

export default {
    parse_login_auth
};