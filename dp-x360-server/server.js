const net = require('net');
const dgram = require('dgram');

const PORT = 19030;

// ==========================================
// UDP Server - Capturing Gameplay Telemetry
// ==========================================
const udpServer = dgram.createSocket('udp4');

udpServer.on('error', (err) => {
    console.error(`[UDP] Server error:\n${err.stack}`);
    udpServer.close();
});

udpServer.on('message', (msg, rinfo) => {
    console.log(`[UDP] Received from ${rinfo.address}:${rinfo.port}`);
    console.log(`[UDP] Data (Hex): ${msg.toString('hex')}`);
    console.log(`[UDP] Data (ASCII): ${msg.toString('ascii')}`);
    console.log('--------------------------------------------------');
});

udpServer.on('listening', () => {
    const address = udpServer.address();
    console.log(`[UDP] Server listening on ${address.address}:${address.port}`);
});

udpServer.bind(PORT);

// ==========================================
// TCP Server - Capturing Handshakes/Auth
// ==========================================
const tcpServer = net.createServer((socket) => {
    console.log(`[TCP] Client connected from: ${socket.remoteAddress}:${socket.remotePort}`);

    socket.on('data', (data) => {
        console.log(`[TCP] Received from ${socket.remoteAddress}`);
        console.log(`[TCP] Data (Hex): ${data.toString('hex')}`);
        console.log(`[TCP] Data (ASCII): ${data.toString('ascii')}`);
        console.log('--------------------------------------------------');
        
        // At this stage we don't know what to reply with yet.
        // Once we analyze the packets via Wireshark, we will send appropriate responses back
        // For example: socket.write(Buffer.from('...'));
    });

    socket.on('end', () => {
        console.log(`[TCP] Client disconnected`);
    });

    socket.on('error', (err) => {
        console.error(`[TCP] Socket error: ${err.message}`);
    });
});

tcpServer.on('error', (err) => {
    console.error(`[TCP] Server error:\n${err.stack}`);
});

tcpServer.listen(PORT, () => {
    console.log(`[TCP] Server listening on port ${PORT}`);
});
