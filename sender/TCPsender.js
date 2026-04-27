import logger from "../logger/logger.js";
import net from 'net';

function send(socket, data, time, Client) {
    socket.write(data);
    logger.print(`[DEBUG] ${time} Sent ${data.length} bytes to ${Client}: ${data.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase()}`);
};

export default send;