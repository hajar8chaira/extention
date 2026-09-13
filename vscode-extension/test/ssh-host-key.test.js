'use strict';

/**
 * Lecture de la clé d'hôte SSH pour approbation explicite.
 *
 * Un serveur SSH en mémoire, écrit indépendamment du client, mène un vrai échange
 * de clés curve25519-sha256 avec des clés d'hôte ed25519, ECDSA P-256 et RSA. Le
 * client doit renvoyer la clé présentée, vérifiée par la signature du serveur, et
 * son empreinte au format OpenSSH (recoupée avec ssh-keygen quand il existe).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { scanSshHostKey, describeHostKey, hostKeyFingerprint } = require('../src/ssh-host-key');

// ------------------------------------------------------------ serveur SSH de test

const u32 = (value) => { const buffer = Buffer.alloc(4); buffer.writeUInt32BE(value); return buffer; };
const str = (value) => { const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'latin1'); return Buffer.concat([u32(data.length), data]); };
function mp(value) {
  let data = value;
  while (data.length > 1 && data[0] === 0) data = data.subarray(1);
  if (data.length === 1 && data[0] === 0) data = Buffer.alloc(0);
  if (data.length && (data[0] & 0x80)) data = Buffer.concat([Buffer.from([0]), data]);
  return str(data);
}
function frame(payload) {
  let padding = 8 - ((5 + payload.length) % 8);
  if (padding < 4) padding += 8;
  return Buffer.concat([u32(1 + payload.length + padding), Buffer.from([padding]), payload, crypto.randomBytes(padding)]);
}
const raw = (base64url) => Buffer.from(base64url, 'base64url');

function hostKeyPair(kind) {
  if (kind === 'ed25519') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
      type: 'ssh-ed25519', algorithm: 'ssh-ed25519',
      blob: Buffer.concat([str('ssh-ed25519'), str(raw(publicKey.export({ format: 'jwk' }).x))]),
      sign: (hash) => Buffer.concat([str('ssh-ed25519'), str(crypto.sign(null, hash, privateKey))])
    };
  }
  if (kind === 'ecdsa') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    return {
      type: 'ecdsa-sha2-nistp256', algorithm: 'ecdsa-sha2-nistp256',
      blob: Buffer.concat([str('ecdsa-sha2-nistp256'), str('nistp256'), str(Buffer.concat([Buffer.from([4]), raw(jwk.x), raw(jwk.y)]))]),
      sign: (hash) => {
        const signature = crypto.sign('sha256', hash, { key: privateKey, dsaEncoding: 'ieee-p1363' });
        return Buffer.concat([str('ecdsa-sha2-nistp256'), str(Buffer.concat([mp(signature.subarray(0, 32)), mp(signature.subarray(32))]))]);
      }
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    type: 'ssh-rsa', algorithm: 'rsa-sha2-512',
    blob: Buffer.concat([str('ssh-rsa'), mp(raw(jwk.e)), mp(raw(jwk.n))]),
    sign: (hash) => Buffer.concat([str('rsa-sha2-512'), str(crypto.sign('sha512', hash, privateKey))])
  };
}

function startFakeSsh({ key, banner = [], tamper = false, kex = 'curve25519-sha256', version = 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5' }) {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', () => {});
      const serverKex = Buffer.concat([
        Buffer.from([20]), crypto.randomBytes(16),
        ...[kex, key.algorithm, 'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256', 'hmac-sha2-256', 'none', 'none', '', ''].map((list) => str(list)),
        Buffer.from([0]), u32(0)
      ]);
      socket.write(`${banner.map((line) => `${line}\r\n`).join('')}${version}\r\n`);
      socket.write(frame(serverKex));
      let buffer = Buffer.alloc(0);
      let clientVersion = '';
      let clientKex = null;
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!clientVersion) {
          const end = buffer.indexOf(0x0a);
          if (end < 0) return;
          clientVersion = buffer.subarray(0, end).toString('latin1').replace(/\r$/, '');
          buffer = buffer.subarray(end + 1);
        }
        while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) {
          const length = buffer.readUInt32BE(0);
          const payload = buffer.subarray(5, 4 + length - buffer[4]);
          buffer = buffer.subarray(4 + length);
          if (payload[0] === 20) clientKex = Buffer.from(payload);
          if (payload[0] === 30) {
            const clientPublic = payload.subarray(5, 5 + payload.readUInt32BE(1));
            const ephemeral = crypto.generateKeyPairSync('x25519');
            const serverPublic = raw(ephemeral.publicKey.export({ format: 'jwk' }).x);
            const shared = crypto.diffieHellman({
              privateKey: ephemeral.privateKey,
              publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: clientPublic.toString('base64url') }, format: 'jwk' })
            });
            const hash = crypto.createHash('sha256').update(Buffer.concat([
              str(clientVersion), str(version), str(clientKex), str(serverKex), str(key.blob), str(clientPublic), str(serverPublic), mp(shared)
            ])).digest();
            const signature = key.sign(hash);
            if (tamper) signature[signature.length - 1] ^= 0xff;
            socket.write(frame(Buffer.concat([Buffer.from([31]), str(key.blob), str(serverPublic), str(signature)])));
          }
        }
      });
    });
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      close: () => new Promise((done) => { for (const socket of sockets) socket.destroy(); server.close(done); })
    }));
  });
}

function rawServer(onConnection) {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = net.createServer((socket) => { sockets.add(socket); socket.on('error', () => {}); onConnection(socket); });
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      close: () => new Promise((done) => { for (const socket of sockets) socket.destroy(); server.close(done); })
    }));
  });
}

/** The fingerprint OpenSSH itself computes, when ssh-keygen is installed. */
function sshKeygenFingerprint(type, keyBase64) {
  const file = path.join(os.tmpdir(), `sc-host-key-${crypto.randomBytes(6).toString('hex')}.pub`);
  fs.writeFileSync(file, `${type} ${keyBase64}\n`);
  try {
    const result = spawnSync('ssh-keygen', ['-l', '-f', file], { encoding: 'utf8', timeout: 20000 });
    if (result.error || result.status !== 0) return null;
    return /SHA256:\S+/.exec(result.stdout)?.[0] || null;
  } finally {
    fs.rmSync(file, { force: true });
  }
}

// ------------------------------------------------------------ tests

for (const kind of ['ed25519', 'ecdsa', 'rsa']) {
  test(`host key ${kind}: presented key returned, signature verified, OpenSSH fingerprint`, async (t) => {
    const key = hostKeyPair(kind);
    const server = await startFakeSsh({ key });
    t.after(() => server.close());
    const scanned = await scanSshHostKey({ host: '127.0.0.1', port: server.port, timeoutMs: 10000 });
    const expected = `SHA256:${crypto.createHash('sha256').update(key.blob).digest('base64').replace(/=+$/, '')}`;
    assert.deepEqual(scanned, { algorithm: key.type, key: key.blob.toString('base64'), fingerprint: expected });
    assert.deepEqual(describeHostKey(scanned.key), scanned);
    const openssh = sshKeygenFingerprint(key.type, scanned.key);
    if (openssh) assert.equal(scanned.fingerprint, openssh, 'same fingerprint as ssh-keygen');
    else t.diagnostic('ssh-keygen unavailable: OpenSSH cross-check skipped');
  });
}

test('pre-version banner lines are tolerated', async (t) => {
  const key = hostKeyPair('ed25519');
  const server = await startFakeSsh({ key, banner: ['Authorized use only.', 'All connections are logged.'] });
  t.after(() => server.close());
  const scanned = await scanSshHostKey({ host: '127.0.0.1', port: server.port });
  assert.equal(scanned.key, key.blob.toString('base64'));
});

test('a host key whose signature does not verify is rejected, never returned', async (t) => {
  const server = await startFakeSsh({ key: hostKeyPair('ed25519'), tamper: true });
  t.after(() => server.close());
  await assert.rejects(scanSshHostKey({ host: '127.0.0.1', port: server.port }), /presented a host key its signature does not match/);
});

test('unreachable, non-SSH, silent or incompatible servers fail with a short reason', async (t) => {
  const closed = await rawServer(() => {});
  const closedPort = closed.port;
  await closed.close();
  await assert.rejects(scanSshHostKey({ host: '127.0.0.1', port: closedPort, timeoutMs: 5000 }), /connection refused on 127\.0\.0\.1:\d+/);

  const web = await rawServer((socket) => socket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n'));
  t.after(() => web.close());
  await assert.rejects(scanSshHostKey({ host: '127.0.0.1', port: web.port }), /is not an SSH server/);

  const silent = await rawServer(() => {});
  t.after(() => silent.close());
  await assert.rejects(scanSshHostKey({ host: '127.0.0.1', port: silent.port, timeoutMs: 1000 }), /no SSH answer from 127\.0\.0\.1:\d+ within 1s/);

  const legacy = await startFakeSsh({ key: hostKeyPair('ed25519'), kex: 'diffie-hellman-group14-sha256' });
  t.after(() => legacy.close());
  await assert.rejects(scanSshHostKey({ host: '127.0.0.1', port: legacy.port }), /offers no curve25519-sha256 key exchange/);
});

test('describeHostKey refuses anything that is not a valid public host key', () => {
  assert.throws(() => describeHostKey('bm90IGEga2V5'), /truncated SSH message|unsupported SSH host key type/);
  assert.throws(() => describeHostKey(Buffer.concat([str('ssh-ed25519'), str(Buffer.alloc(12))])), /invalid ssh-ed25519 host key/);
  assert.throws(() => describeHostKey(Buffer.concat([str('ssh-dss'), str(Buffer.alloc(8))])), /unsupported SSH host key type ssh-dss/);
  const key = hostKeyPair('ed25519');
  assert.match(hostKeyFingerprint(key.blob), /^SHA256:[A-Za-z0-9+/]{43}$/);
});
