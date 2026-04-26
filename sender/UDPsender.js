async function send(packet, server, remote, time) {
    await new Promise((resolve, reject) => {
        server.send(packet, 0, packet.length, remote.port, remote.address, (error) => {
            if (error) { 
                reject(error);
            } else {
                resolve();
            };
        });
    });
}

export default {
    send
};