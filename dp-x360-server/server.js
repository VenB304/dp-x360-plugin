const net = require('net');
const dgram = require('dgram');

const PRUDP_PORT = 19030;
const DIAG_PORT = 19031;

// ==========================================
// Diagnostic Log Receiver (port 19031)
// Receives text log messages from the Xbox 360 plugin's LogToServer()
// ==========================================
const diagServer = dgram.createSocket('udp4');

diagServer.on('error', (err) => {
    console.error(`[DIAG] Server error:\n${err.stack}`);
    diagServer.close();
});

diagServer.on('message', (msg, rinfo) => {
    const timestamp = new Date().toISOString().substr(11, 12); // HH:MM:SS.mmm
    console.log(`[DIAG ${timestamp}] ${msg.toString('ascii')}`);
});

diagServer.on('listening', () => {
    const address = diagServer.address();
    console.log(`[DIAG] Diagnostic log receiver listening on ${address.address}:${address.port}`);
});

diagServer.bind(DIAG_PORT);

// ==========================================
// PRUDP V0 Header Parser
// ==========================================
const PRUDP_TYPES = ['SYN', 'CONNECT', 'DATA', 'DISCONNECT', 'PING'];
const PRUDP_FLAGS = {
    0x01: 'ACK',
    0x02: 'RELIABLE',
    0x04: 'NEED_ACK',
    0x08: 'HAS_SIZE',
};

function parsePRUDPV0Header(buf) {
    if (buf.length < 11) return null;

    // PRUDP V0 header layout:
    // Byte 0:    Source VPort (upper 4 = stream type, lower 4 = port number)
    // Byte 1:    Destination VPort
    // Byte 2:    Type (upper 3-4 bits) + Flags (lower 4 bits)
    // Byte 3:    Session ID
    // Bytes 4-7: Packet Signature (BE)
    // Bytes 8-9: Sequence ID (LE)
    const src = buf[0];
    const dst = buf[1];
    const typeFlags = buf[2];
    const sessionId = buf[3];
    const signature = buf.readUInt32BE(4);
    const sequenceId = buf.readUInt16LE(8);

    const packetType = (typeFlags >> 4) & 0x0F;
    const flags = typeFlags & 0x0F;

    const typeName = PRUDP_TYPES[packetType] || `TYPE_${packetType}`;

    // Decode active flags
    const activeFlags = [];
    for (const [bit, name] of Object.entries(PRUDP_FLAGS)) {
        if (flags & parseInt(bit)) activeFlags.push(name);
    }
    const flagStr = activeFlags.length > 0 ? activeFlags.join('|') : 'NONE';

    return {
        src: { streamType: (src >> 4) & 0x0F, port: src & 0x0F, raw: src },
        dst: { streamType: (dst >> 4) & 0x0F, port: dst & 0x0F, raw: dst },
        typeName,
        packetType,
        flags,
        flagStr,
        sessionId,
        signature,
        sequenceId,
        headerSize: 11 // Minimum V0 header; may vary with optional fields
    };
}

function parseRMCPayload(buf) {
    if (buf.length < 13) return null;

    // RMC format within PRUDP DATA packets:
    // Bytes 0-3:  Payload size (LE)
    // Byte 4:     Protocol ID (bit 7 = isRequest flag, bits 6-0 = protocol)
    // Bytes 5-8:  Call ID (LE)
    // Bytes 9-12: Method ID (LE)
    const payloadSize = buf.readUInt32LE(0);
    const protocolByte = buf[4];
    const isRequest = (protocolByte & 0x80) !== 0;
    const protocolId = protocolByte & 0x7F;
    const callId = buf.readUInt32LE(5);
    const methodId = buf.readUInt32LE(9);

    const PROTOCOLS = {
        0x0A: 'Authentication',
        0x0B: 'SecureConnection',
        0x0E: 'Notification',
        0x12: 'Health',
        0x13: 'Monitoring',
        0x1B: 'PlayerStats',
    };
    const protocolName = PROTOCOLS[protocolId] || `Protocol_0x${protocolId.toString(16).toUpperCase()}`;

    return {
        payloadSize,
        protocolId,
        protocolName,
        isRequest,
        callId,
        methodId,
        paramsOffset: 13, // Parameters start after this
    };
}

// ==========================================
// UDP Server — PRUDP Packet Capture + Parse
// ==========================================
const udpServer = dgram.createSocket('udp4');

udpServer.on('error', (err) => {
    console.error(`[PRUDP] Server error:\n${err.stack}`);
    udpServer.close();
});

udpServer.on('message', (msg, rinfo) => {
    const timestamp = new Date().toISOString().substr(11, 12);
    console.log(`\n[PRUDP ${timestamp}] From ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
    console.log(`[PRUDP] Raw Hex: ${msg.toString('hex')}`);

    const header = parsePRUDPV0Header(msg);
    if (header) {
        console.log(`[PRUDP] Type=${header.typeName} Flags=${header.flagStr} ` +
                    `Session=${header.sessionId} Seq=${header.sequenceId} ` +
                    `Src=0x${header.src.raw.toString(16).padStart(2,'0')} ` +
                    `Dst=0x${header.dst.raw.toString(16).padStart(2,'0')} ` +
                    `Sig=0x${header.signature.toString(16).padStart(8,'0')}`);

        // If DATA packet, try to parse RMC
        if (header.packetType === 2 && msg.length > header.headerSize + 13) {
            const rmcBuf = msg.slice(header.headerSize);
            const rmc = parseRMCPayload(rmcBuf);
            if (rmc) {
                console.log(`[RMC]  ${rmc.isRequest ? 'REQUEST' : 'RESPONSE'} ` +
                           `Protocol=${rmc.protocolName}(0x${rmc.protocolId.toString(16)}) ` +
                           `Method=${rmc.methodId} CallID=${rmc.callId} ` +
                           `PayloadSize=${rmc.payloadSize}`);
                // Log remaining params as hex
                if (rmcBuf.length > rmc.paramsOffset) {
                    const params = rmcBuf.slice(rmc.paramsOffset);
                    console.log(`[RMC]  Params (${params.length} bytes): ${params.toString('hex').substring(0, 128)}${params.length > 64 ? '...' : ''}`);
                }
            }
        }
    } else {
        // Not parseable as PRUDP V0 — log raw
        console.log(`[UDP] Could not parse as PRUDP V0`);
    }
    console.log('--------------------------------------------------');
});

udpServer.on('listening', () => {
    const address = udpServer.address();
    console.log(`[PRUDP] PRUDP packet capture listening on ${address.address}:${address.port}`);
});

udpServer.bind(PRUDP_PORT);

// ==========================================
// TCP Server — Capturing Handshakes/Auth
// ==========================================
const tcpServer = net.createServer((socket) => {
    console.log(`[TCP] Client connected from: ${socket.remoteAddress}:${socket.remotePort}`);

    socket.on('data', (data) => {
        const timestamp = new Date().toISOString().substr(11, 12);
        console.log(`[TCP ${timestamp}] Received from ${socket.remoteAddress} (${data.length} bytes)`);
        console.log(`[TCP] Hex: ${data.toString('hex')}`);
        console.log(`[TCP] ASCII: ${data.toString('ascii').replace(/[^\x20-\x7E]/g, '.')}`);
        console.log('--------------------------------------------------');
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

tcpServer.listen(PRUDP_PORT, () => {
    console.log(`[TCP] TCP server listening on port ${PRUDP_PORT}`);
});

console.log('');
console.log('=== dp-x360-server Diagnostic Server ===');
console.log(`  PRUDP capture:  UDP port ${PRUDP_PORT}`);
console.log(`  TCP capture:    TCP port ${PRUDP_PORT}`);
console.log(`  Plugin diag:    UDP port ${DIAG_PORT}`);
console.log('=========================================');
console.log('');
