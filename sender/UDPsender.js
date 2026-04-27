import logger from "../logger/logger.js";

async function send(data, server, remote, Client, time) {
    await new Promise((resolve, reject) => {
        server.send(data, 0, data.length, remote.port, remote.address, (error) => {
            if (error) { 
                reject(error);
            } else {
                logger.print(`[DEBUG] ${time} Sent ${data.length} bytes to ${Client}: ${data.toString('hex').match(/.{1,2}/g)?.join(' ').toUpperCase()}`);
            };
        });
    });
};

export default send;