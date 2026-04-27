import logger from '../logger/logger.js';
import crypto from 'crypto';
import dgram from 'dgram';

const crc32_table = create_crc32_table();

function get_time() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
};

async function get_RC4_key(keyserver_host, keyserver_port, time, seed) {
    const client = dgram.createSocket('udp4');
    
    return new Promise((resolve, reject) => {
        const seed_bytes = Buffer.alloc(4);
        seed_bytes.writeUInt32LE(seed, 0);
        
        const timeout = setTimeout(() => {
            client.close();
            return logger.error(`[ERROR] ${time} KeyServer Timeout. Skipping...`);
        }, 5000);
        
        client.on('message', (buffer) => {
            clearTimeout(timeout);
            client.close();
            resolve(buffer);
        });
        
        client.on('error', (error) => {
            clearTimeout(timeout);
            client.close();
            reject(error);
        });
        
        client.send(seed_bytes, keyserver_port, keyserver_host, (error) => {
            if (error) {
                clearTimeout(timeout);
                client.close();
                reject(error);
            };
        });
    });
};

function RC4(key, data) {
    const S = new Array(256);
    for (let i = 0; i < 256; i++)
        S[i] = i;
    
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.length]) & 0xFF;
        const tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    };
    
    let x = 0, y = 0;
    for (let k = 0; k < data.length; k++) {
        x = (x + 1) & 0xFF;
        y = (y + S[x]) & 0xFF;
        const tmp = S[x];
        S[x] = S[y];
        S[y] = tmp;
        const t = (S[x] + S[y]) & 0xFF;
        data[k] ^= S[t];
    };
};

function create_crc32_table() {
    const table = new Array(256);
    const poly = 0xEDB88320;
    
    for (let i = 0; i < 256; i++) {
        let crc = i;
        for (let j = 0; j < 8; j++) {
            crc = (crc & 1) !== 0 ? (crc >>> 1) ^ poly : (crc >>> 1);
        }
        table[i] = crc >>> 0;
    }
    return table;
};

function calculate_crc32(buffer, salt) {
    let crc = salt >>> 0;
    
    for (let i = 0; i < buffer.length; i++) {
        crc = crc32_table[(crc ^ buffer[i]) & 0xFF] ^ (crc >>> 8);
    }
    
    return crc >>> 0;
};

function calculate_seed(data, remote, PacketType, supernode_host, time) {
    const transID_bytes = Buffer.alloc(2);
    data.copy(transID_bytes, 0, 0, 2);
    const transID_uint = ((transID_bytes[0] << 8) | transID_bytes[1]) >>> 0;
    
    const iv_bytes = Buffer.alloc(4);
    data.copy(iv_bytes, 0, 4, 8);
    const iv_uint = ((iv_bytes[0] << 24) | (iv_bytes[1] << 16) | (iv_bytes[2] << 8) | iv_bytes[3]) >>> 0;
    
    const supernode_host_bytes = supernode_host.split('.').map(Number);
    const supernode_ip_uint = ((supernode_host_bytes[0] << 24) | 
                               (supernode_host_bytes[1] << 16) | 
                               (supernode_host_bytes[2] << 8) | 
                               supernode_host_bytes[3]) >>> 0;
    
    const client_ip_bytes = remote.address.split('.').map(Number);
    const client_ip_uint = ((client_ip_bytes[0] << 24) | 
                            (client_ip_bytes[1] << 16) | 
                            (client_ip_bytes[2] << 8) | 
                            client_ip_bytes[3]) >>> 0;
    
    const to_crc = Buffer.alloc(12);
    
    to_crc.writeUInt32BE(supernode_ip_uint, 0);
    to_crc.writeUInt32BE(client_ip_uint, 4);
    
    to_crc[8] = transID_uint & 0xFF;
    to_crc[9] = (transID_uint >> 8) & 0xFF;
    to_crc[10] = 0;
    to_crc[11] = 0;
    
    const crc_to_crc = calculate_crc32(to_crc, 0xFFFFFFFF);
    
    let seed;
    if (PacketType === 0x02) {
        seed = (crc_to_crc ^ iv_uint) >>> 0;
    } else if (PacketType === 0x03) {
        seed = (transID_uint ^ iv_uint) >>> 0;
    } else {
        return 0;
    };
    
    return seed;
};

function networkToHostOrder(value) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value, 0);
    return buffer.readUInt32LE(0);
};

function hostToNetworkOrder(value) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value, 0);
    return buffer.readUInt32BE(0);
};

function create_RC4_stream(key) {
    const S = new Array(256);
    for (let i = 0; i < 256; i++)
        S[i] = i;
    
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.length]) & 0xFF;
        const tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    };

    let x = 0;
    let y = 0;

    function update(data) {
        const out = Buffer.from(data);
        for (let k = 0; k < out.length; k++) {
            x = (x + 1) & 0xFF;
            y = (y + S[x]) & 0xFF;
            const tmp = S[x];
            S[x] = S[y];
            S[y] = tmp;
            const t = (S[x] + S[y]) & 0xFF;
            out[k] ^= S[t];
        }
        return out;
    };

    return { update };
};

function read_int(buf, offset) {
    let result = 0;
    let shift = 0;
    let pos = offset;

    while (true) {
        const byte = buf[pos];
        result |= (byte & 0x7F) << shift;
        pos++;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    };

    return { value: result, size: pos - offset };
};

function write_int(value) {
    const out = [];

    let v = value >>> 0;

    while (v >= 0x80) {
        out.push((v & 0x7F) | 0x80);
        v >>>= 7;
    };

    out.push(v & 0x7F);

    return Buffer.from(out);
};

function specialSHA(sessionKey) {
    const ResSz = 32;
    const salts = [
        Buffer.from([0x00, 0x00, 0x00, 0x00]),
        Buffer.from([0x00, 0x00, 0x00, 0x01])
    ];
    
    const result = Buffer.alloc(ResSz);
    let idx = 0;
    let remaining = ResSz;
    
    while (remaining > 20) {
        const hash = crypto.createHash('sha1');
        hash.update(salts[idx]);
        hash.update(sessionKey);
        const digest = hash.digest();
        digest.copy(result, idx * 20, 0, 20);
        idx++;
        remaining -= 20;
    };
    
    const hash = crypto.createHash('sha1');
    hash.update(salts[idx]);
    hash.update(sessionKey);
    const digest = hash.digest();
    digest.copy(result, idx * 20, 0, remaining);
    
    return result;
};

function aes_ctr_decrypt(encrypted_data, key, is_response = true) {
    const iv = Buffer.alloc(16, 0);
    
    if (is_response) {
        iv[3] = 0x01;
        iv[7] = 0x01;
    };

    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    cipher.setAutoPadding(false);
    
    const decrypted = Buffer.concat([
        cipher.update(encrypted_data),
        cipher.final()
    ]);
    
    return decrypted;
};

function aes_ctr_encrypt(data, key) {
    const iv = Buffer.alloc(16, 0x00);
    iv[3] = 0x01;
    iv[7] = 0x01;

    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);

    const encrypted = Buffer.concat([
        cipher.update(data),
        cipher.final()
    ]);
    
    return encrypted;
};

export default {
    get_time,
    get_RC4_key,
    RC4,
    calculate_crc32,
    calculate_seed,
    networkToHostOrder,
    hostToNetworkOrder,
    create_RC4_stream,
    read_int,
    write_int,
    specialSHA,
    aes_ctr_decrypt,
    aes_ctr_encrypt
};