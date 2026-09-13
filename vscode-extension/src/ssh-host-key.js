'use strict';

/**
 * Reads the SSH host key a server presents, so a person can approve it before
 * Jenkins trusts it.
 *
 * Only the key exchange runs: no authentication, no credential, no session. The
 * exchange goes just far enough to verify the server's signature over the
 * exchange hash, which proves the server holds the private host key it presents.
 * The connection is then closed. Nothing here depends on an npm package.
 */

const crypto = require('crypto');
const net = require('net');

const CLIENT_VERSION = 'SSH-2.0-SecurityCenter_HostKeyCheck';
const MSG = Object.freeze({ DISCONNECT: 1, KEXINIT: 20, KEX_ECDH_INIT: 30, KEX_ECDH_REPLY: 31 });
const KEX_ALGORITHMS = Object.freeze(['curve25519-sha256', 'curve25519-sha256@libssh.org']);
const HOST_KEY_ALGORITHMS = Object.freeze(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256']);
const HOST_KEY_TYPES = Object.freeze(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa']);
// Offered only so the server accepts the negotiation; the session never starts.
const CIPHERS = Object.freeze(['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-ctr', 'aes256-ctr']);
const MACS = Object.freeze(['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512']);
const CURVES = Object.freeze({
  'ecdsa-sha2-nistp256': { crv: 'P-256', hash: 'sha256', size: 32 },
  'ecdsa-sha2-nistp384': { crv: 'P-384', hash: 'sha384', size: 48 },
  'ecdsa-sha2-nistp521': { crv: 'P-521', hash: 'sha512', size: 66 }
});

const uint32 = (value) => { const buffer = Buffer.alloc(4); buffer.writeUInt32BE(value >>> 0); return buffer; };
const sshString = (value) => {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'latin1');
  return Buffer.concat([uint32(data.length), data]);
};
const nameList = (names) => sshString(names.join(','));
const base64url = (buffer) => Buffer.from(buffer).toString('base64url');

/** The unsigned big-endian integer of an SSH mpint or raw value, without leading zeros. */
function unsigned(buffer) {
  let start = 0;
  while (start < buffer.length - 1 && buffer[start] === 0) start += 1;
  return buffer.subarray(start);
}

function mpint(buffer) {
  let data = unsigned(buffer);
  if (data.length === 1 && data[0] === 0) data = Buffer.alloc(0);
  if (data.length && data[0] & 0x80) data = Buffer.concat([Buffer.from([0]), data]);
  return sshString(data);
}

class Reader {
  constructor(buffer) { this.buffer = buffer; this.offset = 0; }
  need(length) { if (this.offset + length > this.buffer.length) throw new Error('truncated SSH message'); }
  byte() { this.need(1); return this.buffer[this.offset++]; }
  skip(length) { this.need(length); this.offset += length; }
  uint32() { this.need(4); const value = this.buffer.readUInt32BE(this.offset); this.offset += 4; return value; }
  string() { const length = this.uint32(); this.need(length); const value = this.buffer.subarray(this.offset, this.offset + length); this.offset += length; return value; }
  text() { return this.string().toString('latin1'); }
}

/** A Node public key for an SSH host key blob, and the blob's key type. */
function publicKeyFromBlob(blob) {
  const reader = new Reader(blob);
  const type = reader.text();
  if (type === 'ssh-ed25519') {
    const raw = reader.string();
    if (raw.length !== 32) throw new Error('invalid ssh-ed25519 host key');
    return { type, key: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: base64url(raw) }, format: 'jwk' }) };
  }
  if (CURVES[type]) {
    reader.text();
    const point = reader.string();
    const { crv, size } = CURVES[type];
    if (point.length !== 1 + 2 * size || point[0] !== 4) throw new Error(`invalid ${type} host key`);
    return {
      type,
      key: crypto.createPublicKey({ key: { kty: 'EC', crv, x: base64url(point.subarray(1, 1 + size)), y: base64url(point.subarray(1 + size)) }, format: 'jwk' })
    };
  }
  if (type === 'ssh-rsa') {
    const exponent = unsigned(reader.string());
    const modulus = unsigned(reader.string());
    return { type, key: crypto.createPublicKey({ key: { kty: 'RSA', n: base64url(modulus), e: base64url(exponent) }, format: 'jwk' }) };
  }
  throw new Error(`unsupported SSH host key type ${type}`);
}

function fixed(buffer, size) {
  const value = unsigned(buffer);
  if (value.length > size) throw new Error('invalid ECDSA signature');
  return Buffer.concat([Buffer.alloc(size - value.length), value]);
}

/** Whether `signatureBlob` is the host key's signature over the exchange hash. */
function verifyHostKeySignature(blob, signatureBlob, exchangeHash) {
  const { type, key } = publicKeyFromBlob(blob);
  const reader = new Reader(signatureBlob);
  const algorithm = reader.text();
  const signature = reader.string();
  if (type === 'ssh-ed25519' && algorithm === 'ssh-ed25519') return crypto.verify(null, exchangeHash, key, signature);
  if (CURVES[type] && algorithm === type) {
    const inner = new Reader(signature);
    const { hash, size } = CURVES[type];
    const p1363 = Buffer.concat([fixed(inner.string(), size), fixed(inner.string(), size)]);
    return crypto.verify(hash, exchangeHash, { key, dsaEncoding: 'ieee-p1363' }, p1363);
  }
  if (type === 'ssh-rsa' && (algorithm === 'rsa-sha2-256' || algorithm === 'rsa-sha2-512')) {
    return crypto.verify(algorithm === 'rsa-sha2-512' ? 'sha512' : 'sha256', exchangeHash, key, signature);
  }
  return false;
}

/** OpenSSH-style fingerprint: SHA256 of the key blob, unpadded base64. */
function hostKeyFingerprint(key) {
  const blob = Buffer.isBuffer(key) ? key : Buffer.from(String(key || ''), 'base64');
  return `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
}

/** A validated host key: its type, its base64 blob and its fingerprint. Throws on anything else. */
function describeHostKey(key) {
  const blob = Buffer.isBuffer(key) ? key : Buffer.from(String(key || ''), 'base64');
  const { type } = publicKeyFromBlob(blob);
  if (!HOST_KEY_TYPES.includes(type)) throw new Error(`unsupported SSH host key type ${type}`);
  return { algorithm: type, key: blob.toString('base64'), fingerprint: hostKeyFingerprint(blob) };
}

function clientKexInit() {
  return Buffer.concat([
    Buffer.from([MSG.KEXINIT]), crypto.randomBytes(16),
    nameList(KEX_ALGORITHMS), nameList(HOST_KEY_ALGORITHMS),
    nameList(CIPHERS), nameList(CIPHERS), nameList(MACS), nameList(MACS),
    nameList(['none']), nameList(['none']), nameList([]), nameList([]),
    Buffer.from([0]), uint32(0)
  ]);
}

function packet(payload) {
  let padding = 8 - ((5 + payload.length) % 8);
  if (padding < 4) padding += 8;
  return Buffer.concat([uint32(1 + payload.length + padding), Buffer.from([padding]), payload, crypto.randomBytes(padding)]);
}

/** The server's key exchange and host key algorithm lists. */
function serverAlgorithms(kexInit) {
  const reader = new Reader(kexInit);
  reader.byte();
  reader.skip(16);
  return { kex: reader.text().split(','), hostKeys: reader.text().split(',') };
}

function networkReason(error, host, port) {
  if (error?.code === 'ECONNREFUSED') return `connection refused on ${host}:${port}`;
  if (['ENOTFOUND', 'EAI_AGAIN'].includes(error?.code)) return `host name ${host} not found`;
  if (['ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH'].includes(error?.code)) return `${host}:${port} is unreachable`;
  return error?.code ? `network error ${error.code}` : 'network error';
}

/**
 * Connects to `host:port`, runs the SSH key exchange and resolves with the
 * verified host key. Rejects with a short reason; nothing is ever trusted here.
 */
function scanSshHostKey({ host, port = 22, timeoutMs = 10000, connect = net.connect } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let socket = null;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket) socket.destroy();
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error(`no SSH answer from ${host}:${port} within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs);
    const clientKex = clientKexInit();
    const ephemeral = crypto.generateKeyPairSync('x25519');
    const clientPublic = Buffer.from(ephemeral.publicKey.export({ format: 'jwk' }).x, 'base64url');
    let buffer = Buffer.alloc(0);
    let serverVersion = '';
    let serverKex = null;

    try { socket = connect({ host, port }); } catch (error) { return finish(new Error(networkReason(error, host, port))); }
    socket.on('connect', () => {
      socket.write(`${CLIENT_VERSION}\r\n`);
      socket.write(packet(clientKex));
    });
    socket.on('error', (error) => finish(new Error(networkReason(error, host, port))));
    socket.on('close', () => finish(new Error(`${host}:${port} closed the connection before presenting a host key`)));
    socket.on('data', (chunk) => {
      try {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > 256 * 1024) throw new Error(`${host}:${port} is not an SSH server`);
        while (!serverVersion) {
          const end = buffer.indexOf(0x0a);
          if (end < 0) {
            if (buffer.length > 8192) throw new Error(`${host}:${port} is not an SSH server`);
            return;
          }
          const line = buffer.subarray(0, end).toString('latin1').replace(/\r$/, '');
          buffer = buffer.subarray(end + 1);
          if (line.startsWith('SSH-')) {
            if (!/^SSH-(2\.0|1\.99)-/.test(line)) throw new Error(`${host}:${port} does not speak SSH 2`);
            serverVersion = line;
          } else if (/^(HTTP\/|<)/i.test(line)) {
            throw new Error(`${host}:${port} is not an SSH server`);
          }
        }
        while (buffer.length >= 4) {
          const length = buffer.readUInt32BE(0);
          if (length < 5 || length > 64 * 1024) throw new Error(`${host}:${port} sent an invalid SSH packet`);
          if (buffer.length < 4 + length) return;
          const paddingLength = buffer[4];
          if (paddingLength >= length) throw new Error(`${host}:${port} sent an invalid SSH packet`);
          const payload = buffer.subarray(5, 4 + length - paddingLength);
          buffer = buffer.subarray(4 + length);
          if (payload[0] === MSG.KEXINIT && !serverKex) {
            serverKex = Buffer.from(payload);
            const offered = serverAlgorithms(serverKex);
            if (!offered.kex.some((name) => KEX_ALGORITHMS.includes(name))) throw new Error(`${host}:${port} offers no curve25519-sha256 key exchange`);
            if (!offered.hostKeys.some((name) => HOST_KEY_ALGORITHMS.includes(name))) throw new Error(`${host}:${port} offers no supported host key type`);
            socket.write(packet(Buffer.concat([Buffer.from([MSG.KEX_ECDH_INIT]), sshString(clientPublic)])));
          } else if (payload[0] === MSG.KEX_ECDH_REPLY && serverKex) {
            const reply = new Reader(payload.subarray(1));
            const hostKey = Buffer.from(reply.string());
            const serverPublic = reply.string();
            const signature = reply.string();
            if (serverPublic.length !== 32) throw new Error(`${host}:${port} sent an invalid key exchange reply`);
            const shared = crypto.diffieHellman({
              privateKey: ephemeral.privateKey,
              publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: base64url(serverPublic) }, format: 'jwk' })
            });
            const exchangeHash = crypto.createHash('sha256').update(Buffer.concat([
              sshString(CLIENT_VERSION), sshString(serverVersion), sshString(clientKex), sshString(serverKex),
              sshString(hostKey), sshString(clientPublic), sshString(serverPublic), mpint(shared)
            ])).digest();
            if (!verifyHostKeySignature(hostKey, signature, exchangeHash)) {
              throw new Error(`${host}:${port} presented a host key its signature does not match`);
            }
            return finish(null, describeHostKey(hostKey));
          } else if (payload[0] === MSG.DISCONNECT) {
            throw new Error(`${host}:${port} refused the SSH key exchange`);
          }
        }
      } catch (error) {
        finish(error);
      }
    });
  });
}

module.exports = {
  HOST_KEY_TYPES, scanSshHostKey, describeHostKey, hostKeyFingerprint, verifyHostKeySignature, publicKeyFromBlob
};
