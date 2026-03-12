const dgram = require('dgram');
const server = dgram.createSocket('udp4');

const LOCAL_IP = '192.168.50.47';
const UPSTREAM_DNS = '8.8.8.8';
const DNS_PORT = 53;

// Domains to redirect to our local OpenParty server
const REDIRECT_DOMAINS = [
  'public-ubiservices.ubi.com',
  'public-ws-ubiservices.ubi.com',
  'api-ubiservices.ubi.com',
  'uplay-ubiservices.ubi.com',
  'connect.ubi.com',
  'ubiservices.ubi.com',
  'gaap.ubiservices.ubi.com',
  'useast1-uat-public-ubiservices.ubi.com',
  'pdc-prd-jdbloom.ubisoft.org',
  'v2.phonescoring.jd.ubisoft.com',
  'phonescoring.jd.ubisoft.com',
  'jd.ubisoft.com',
  'gamecfg-mob.ubi.com',
  'ROG-Server.ubisoft.org',
  'ncsa-storm.ubi.com',
  'emea-storm.ubi.com',
  'apac-storm.ubi.com',
  'ap-southeast-2-storm.ubi.com',
  'prod-public-ubiservices.ubi.com',
  'msr-public-ubiservices.ubi.com',
  'msr-prod-public-ubiservices.ubi.com',
];

function parseDomainName(buf, offset) {
  let labels = [];
  let jumped = false;
  let savedOffset = -1;

  while (true) {
    if (offset >= buf.length) break;
    let len = buf[offset];

    if (len === 0) {
      offset++;
      break;
    }

    // DNS compression pointer
    if ((len & 0xC0) === 0xC0) {
      if (savedOffset === -1) savedOffset = offset + 2;
      offset = ((len & 0x3F) << 8) | buf[offset + 1];
      jumped = true;
      continue;
    }

    offset++;
    if (offset + len > buf.length) break;
    labels.push(buf.slice(offset, offset + len).toString('ascii'));
    offset += len;
  }

  return {
    name: labels.join('.'),
    nextOffset: jumped ? savedOffset : offset
  };
}

function buildDnsResponse(query, questionEnd, ip) {
  // Build a clean response: header (12) + question section + answer (16)
  const questionSection = query.slice(12, questionEnd);
  const responseLen = 12 + questionSection.length + 16;
  const response = Buffer.alloc(responseLen);

  // --- Header (12 bytes) ---
  // Transaction ID from query
  response[0] = query[0];
  response[1] = query[1];
  // Flags: QR=1, AA=1, RD=1, RA=1
  response[2] = 0x85;
  response[3] = 0x80;
  // QDCOUNT = 1
  response[4] = 0x00;
  response[5] = 0x01;
  // ANCOUNT = 1
  response[6] = 0x00;
  response[7] = 0x01;
  // NSCOUNT = 0
  response[8] = 0x00;
  response[9] = 0x00;
  // ARCOUNT = 0
  response[10] = 0x00;
  response[11] = 0x00;

  // --- Question section (copy from query) ---
  questionSection.copy(response, 12);

  // --- Answer section (16 bytes) ---
  const ao = 12 + questionSection.length; // answer offset

  // Name pointer -> offset 12 (start of question name)
  response[ao + 0] = 0xC0;
  response[ao + 1] = 0x0C;
  // Type A
  response[ao + 2] = 0x00;
  response[ao + 3] = 0x01;
  // Class IN
  response[ao + 4] = 0x00;
  response[ao + 5] = 0x01;
  // TTL = 60s
  response.writeUInt32BE(60, ao + 6);
  // RDLENGTH = 4
  response[ao + 10] = 0x00;
  response[ao + 11] = 0x04;
  // IP address
  const parts = ip.split('.');
  response[ao + 12] = parseInt(parts[0]);
  response[ao + 13] = parseInt(parts[1]);
  response[ao + 14] = parseInt(parts[2]);
  response[ao + 15] = parseInt(parts[3]);

  return response;
}

function forwardToUpstream(msg, rinfo) {
  const client = dgram.createSocket('udp4');
  client.send(msg, 0, msg.length, DNS_PORT, UPSTREAM_DNS, (err) => {
    if (err) {
      console.log(`[DNS] Forward error: ${err.message}`);
      client.close();
    }
  });
  client.on('message', (response) => {
    server.send(response, 0, response.length, rinfo.port, rinfo.address);
    client.close();
  });
  client.on('error', () => client.close());
  setTimeout(() => { try { client.close(); } catch (e) {} }, 3000);
}

server.on('message', (msg, rinfo) => {
  if (msg.length < 12) return;

  // Parse question
  const qdcount = msg.readUInt16BE(4);
  if (qdcount < 1) {
    forwardToUpstream(msg, rinfo);
    return;
  }

  const { name, nextOffset } = parseDomainName(msg, 12);

  // QTYPE and QCLASS are right after the domain name
  if (nextOffset + 4 > msg.length) {
    forwardToUpstream(msg, rinfo);
    return;
  }

  const qtype = msg.readUInt16BE(nextOffset);
  const qclass = msg.readUInt16BE(nextOffset + 2);
  const questionEnd = nextOffset + 4; // end of question section

  const domainLower = name.toLowerCase();

  // Check if this domain should be redirected
  const shouldRedirect = REDIRECT_DOMAINS.some(d => domainLower === d || domainLower.endsWith('.' + d));

  if (shouldRedirect && qtype === 1 && qclass === 1) {
    console.log(`[DNS] REDIRECT ${name} -> ${LOCAL_IP} (from ${rinfo.address}:${rinfo.port})`);
    const response = buildDnsResponse(msg, questionEnd, LOCAL_IP);
    server.send(response, 0, response.length, rinfo.port, rinfo.address);
  } else {
    if (shouldRedirect) {
      console.log(`[DNS] Forward non-A query for ${name} (type=${qtype}, class=${qclass}) from ${rinfo.address}`);
    } else {
      console.log(`[DNS] PASS ${name} -> upstream (from ${rinfo.address})`);
    }
    forwardToUpstream(msg, rinfo);
  }
});

server.on('error', (err) => {
  console.error(`[DNS] Server error: ${err.message}`);
  if (err.code === 'EACCES') {
    console.error('[DNS] Port 53 requires admin/elevated privileges!');
    console.error('[DNS] Run this terminal as Administrator.');
  }
  if (err.code === 'EADDRINUSE') {
    console.error('[DNS] Port 53 is already in use! Kill the other process first.');
  }
  server.close();
});

server.on('listening', () => {
  const addr = server.address();
  console.log(`[DNS] Redirect server listening on ${addr.address}:${addr.port}`);
  console.log(`[DNS] Redirecting ${REDIRECT_DOMAINS.length} Ubisoft domains -> ${LOCAL_IP}`);
  console.log(`[DNS] All other queries forwarded to ${UPSTREAM_DNS}`);
  console.log(`[DNS] Set your Xbox 360 Primary DNS to: ${LOCAL_IP}`);
  console.log('');
});

server.bind(DNS_PORT, '0.0.0.0');
