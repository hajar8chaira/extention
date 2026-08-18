'use strict';

/**
 * Secret redaction for everything that can reach the local model.
 *
 * The previous redaction asked one question — « is this identifier called
 * something like a secret? » — and a credential named `awsAccessKeyId` or
 * `dbConn` answered no, so its value was never looked at. This module adds the
 * other question: « does this *value* look like a credential? », which is the
 * one that still works when the name is unknown.
 *
 * Both questions are kept. Name-based rules catch an opaque value under an
 * obvious name (`password = "hunter2"`); value-based rules catch an obvious
 * credential under an opaque name. Neither alone is enough.
 *
 * The bar for value-based redaction is deliberately high: a recognisable
 * credential shape, a structured position, or high entropy *inside a
 * credential-bearing position*. Free-floating long strings are left alone, so
 * hashes, versions and ordinary literals still reach the model as context.
 */

/** The single marker. Existing Gitleaks handling matches on it verbatim. */
const REDACTED = '[REDACTED]';

// ---------------------------------------------------------------- by name

const SECRET_ASSIGNMENT = /\b(api[_-]?key|token|password|passwd|pwd|secret|authorization|credential)s?\s*=\s*(["'`])([^\r\n"'`]+)\2/gi;
const SECRET_JSON = /(["'](?:api[_-]?key|token|password|passwd|secret|authorization|credential)s?["']\s*:\s*)(["'])([^\r\n"']+)\2/gi;
const SECRET_YAML = /^(\s*(?:key|api[_-]?key|token|password|passwd|secret|authorization|credential)s?\s*:\s*)(["']?)([^\r\n#"']+)(["']?)(\s*(?:#.*)?)$/gim;

/**
 * Key names that denote a credential without containing any of the words above.
 * An explicit list rather than a loose pattern: `aws_access_key_id` must match,
 * `primary_key` and `sort_key` must not.
 */
const CREDENTIAL_KEY_SOURCE = [
  'aws[_-]?access[_-]?key[_-]?id', 'aws[_-]?secret[_-]?access[_-]?key', 'aws[_-]?session[_-]?token',
  'client[_-]?secret', 'private[_-]?key', 'refresh[_-]?token', 'access[_-]?token',
  'passphrase', 'conn(?:ection)?[_-]?string', 'dsn'
].join('|');

const CREDENTIAL_KEY_ASSIGNMENT = new RegExp(
  '((?:' + CREDENTIAL_KEY_SOURCE + ')\\s*[:=]\\s*)(["\'`]?)([^\\r\\n#"\'`]+)(["\'`]?)', 'gi'
);

// --------------------------------------------------------------- by value

/**
 * Credential shapes that identify themselves. Each has an issuer-defined prefix
 * and length, so matching one is recognition, not a guess.
 */
const CREDENTIAL_PREFIX = new RegExp([
  '(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}',
  'gh[pousr]_[A-Za-z0-9]{36,255}',
  'github_pat_[A-Za-z0-9_]{22,255}',
  'glpat-[A-Za-z0-9_-]{20,}',
  'xox[abposr]-[A-Za-z0-9-]{10,}',
  'sk-[A-Za-z0-9_-]{16,}',
  'pk-[A-Za-z0-9_-]{16,}',
  'AIza[0-9A-Za-z_-]{35}',
  'SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}',
  'npm_[A-Za-z0-9]{36}',
  'dop_v1_[a-f0-9]{64}'
].join('|'), 'g');

/**
 * A JWT: three base64url segments whose header begins `eyJ`. Requiring both the
 * decoded-header prefix and three segments is what keeps `1.2.3` and
 * `lodash.merge.js` out of the match.
 */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

/** Private key blocks: the whole body goes, never a partial line. */
const PRIVATE_KEY_BLOCK = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g;
/** A block truncated by the excerpt window must not leak its body either. */
const PRIVATE_KEY_OPEN = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*/g;

/**
 * Credentials inside a URL or connection string.
 *
 * Only the userinfo is removed. Scheme, host, port and path stay: the model
 * needs to see that this *is* a database URL to reason about the code, and the
 * host is not treated as secret elsewhere in Security Center — removing it would
 * invent a privacy rule the rest of the product does not have.
 */
// The username may be empty — `redis://:password@host` is the documented form —
// so the user part is `*`, not `+`. The `@` is what marks it as credentials.
const URL_CREDENTIALS = /\b([a-z][a-z0-9+.-]*:\/\/)([^\s/@:"'`]*)(?::([^\s/@"'`]*))?@/gi;

/** `Authorization: Bearer x`, `Authorization: Basic x`, `X-API-Key: x`. */
const AUTH_HEADER = /((?:authorization|proxy-authorization|x-api-key|x-auth-token|api-key)\s*[:=]\s*["'`]?)(?:(bearer|basic|token|digest)\s+)?([^\s"'`,;\r\n]+)/gi;

/** A credential passed as a query or form parameter. */
const CREDENTIAL_PARAM = /\b((?:access_token|api_key|apikey|auth|client_secret|id_token|password|refresh_token|secret|token)=)([^\s&"'`<>#\r\n]+)/gi;

/** `user:password` where the value is explicitly labelled as credentials. */
const CREDENTIAL_PAIR = /((?:credential|login|auth)s?\s*[:=]\s*["'`])([^\s"'`:]+):([^\s"'`]+)(["'`])/gi;

/** Any quoted value on the right of an assignment — the entropy fallback's scope. */
const QUOTED_ASSIGNMENT = /([A-Za-z_$][\w$.-]*\s*[:=]\s*)(["'`])([^\r\n"'`]+)\2/g;

/**
 * High-entropy fallback, applied only in a credential-bearing position.
 *
 * Shannon entropy with a length floor. It runs after the shaped rules and only
 * on the value side of an assignment, so it never sees free-standing prose.
 * `abcdef123456` (entropy ≈ 3.6) and `1.2.3` stay; a 20+ character random token
 * (entropy ≥ 4.0) does not.
 */
const ENTROPY_THRESHOLD = 4.0;
const ENTROPY_MIN_LENGTH = 20;

function shannonEntropy(value) {
  const text = String(value);
  if (!text) return 0;
  const counts = new Map();
  for (const character of text) counts.set(character, (counts.get(character) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / text.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function looksLikeSecretValue(value) {
  const text = String(value || '').trim();
  if (text.length < ENTROPY_MIN_LENGTH) return false;
  // Whitespace means prose, not a credential.
  if (/\s/.test(text)) return false;
  // An environment reference is the fix, not the secret.
  if (/^\$\{|^\$[A-Z_]+$|^process\.env|^os\.environ|^import\.meta\.env/.test(text)) return false;
  // A path or a URL without userinfo is structure, not a credential.
  if (/^(?:\.{0,2}\/|[a-z][a-z0-9+.-]*:\/\/)/i.test(text)) return false;
  return shannonEntropy(text) >= ENTROPY_THRESHOLD;
}

/**
 * Redacts secrets from a string.
 *
 * Order matters: private key blocks first — they span lines and the
 * line-oriented rules would shred them into partially-leaked fragments — then
 * self-identifying shapes, then structural positions, then names, then entropy.
 */
function redactSecrets(value) {
  let text = String(value || '');

  text = text.replace(PRIVATE_KEY_BLOCK, REDACTED + '_PRIVATE_KEY');
  text = text.replace(PRIVATE_KEY_OPEN, REDACTED + '_PRIVATE_KEY');

  text = text.replace(CREDENTIAL_PREFIX, REDACTED);
  text = text.replace(JWT, REDACTED);

  text = text.replace(URL_CREDENTIALS, (match, scheme) => scheme + REDACTED + '@');
  text = text.replace(AUTH_HEADER, (match, prefix, scheme) =>
    prefix + (scheme ? scheme + ' ' : '') + REDACTED);
  text = text.replace(CREDENTIAL_PARAM, (match, prefix) => prefix + REDACTED);
  text = text.replace(CREDENTIAL_PAIR, (match, prefix, user, password, quote) =>
    prefix + REDACTED + quote);

  // Already-redacted values are left alone. Without this the name-based rules
  // would re-match what the structural rules just produced and swallow the
  // structure with it — « Authorization: Bearer [REDACTED] » would collapse to
  // « Authorization: [REDACTED] », losing the scheme for no gain.
  const keepRedacted = (replacer) => (match, ...groups) =>
    match.includes(REDACTED) ? match : replacer(match, ...groups);

  text = text.replace(SECRET_ASSIGNMENT, keepRedacted((match, name, quote) =>
    name + ' = ' + quote + REDACTED + quote));
  text = text.replace(SECRET_JSON, keepRedacted((match, prefix, quote) =>
    prefix + quote + REDACTED + quote));
  text = text.replace(SECRET_YAML, keepRedacted((match, prefix, open, body, close, trailing) =>
    prefix + open + REDACTED + close + trailing));
  text = text.replace(CREDENTIAL_KEY_ASSIGNMENT, keepRedacted((match, prefix, open, body, close) =>
    prefix + open + REDACTED + close));

  text = text.replace(QUOTED_ASSIGNMENT, (match, prefix, quote, body) =>
    !match.includes(REDACTED) && looksLikeSecretValue(body) ? prefix + quote + REDACTED + quote : match);

  return text;
}

/**
 * The last thing that touches data before it leaves for the model.
 *
 * Applied to every outgoing message whatever built the prompt, so a future
 * prompt path that forgets to sanitize its own inputs is still covered. It calls
 * the same function as the earlier layer on purpose: one definition of what a
 * secret is, applied twice, rather than two definitions that drift apart.
 */
function redactOutgoingMessages(messages) {
  return (Array.isArray(messages) ? messages : []).map((message) => (
    message && typeof message.content === 'string'
      ? { ...message, content: redactSecrets(message.content) }
      : message
  ));
}

module.exports = {
  REDACTED, ENTROPY_THRESHOLD, ENTROPY_MIN_LENGTH,
  shannonEntropy, looksLikeSecretValue, redactSecrets, redactOutgoingMessages
};
