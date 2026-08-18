'use strict';

/**
 * Authenticated DAST profiles.
 *
 * A profile describes *how* to authenticate — a bearer token, a session cookie, a
 * custom header — without ever holding the credential. The secret lives in VS Code
 * SecretStorage under a key derived from the profile id; the profile itself is
 * plain configuration and is safe to persist, render and put in scan history.
 *
 * The separation is the whole point. Everything this module returns can be written
 * to `settings.json`, printed in a log, embedded in a report or shown in a webview
 * without leaking anything. The credential is fetched, used for one request and
 * never stored alongside the profile.
 *
 * `maskedValue` exists so a developer can confirm *which* token is configured
 * without the token being recoverable from what is displayed.
 */

const AUTH_KIND = Object.freeze({
  NONE: 'none',
  BEARER: 'bearer',
  COOKIE: 'cookie',
  HEADER: 'header'
});

/** Whether a profile has been proven to work, and when. */
const AUTH_STATUS = Object.freeze({
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  CONFIGURED: 'CONFIGURED',
  VALID: 'VALID',
  INVALID: 'INVALID',
  EXPIRED: 'EXPIRED',
  UNKNOWN: 'UNKNOWN'
});

const AUTH_STATUS_LABELS = Object.freeze({
  NOT_CONFIGURED: 'Aucun profil',
  CONFIGURED: 'Configuré — jamais validé',
  VALID: 'Session valide',
  INVALID: 'Authentification refusée',
  EXPIRED: 'Session expirée',
  UNKNOWN: 'État inconnu'
});

/** Header names a profile may set. Anything else is refused. */
const ALLOWED_CUSTOM_HEADER = /^[A-Za-z][A-Za-z0-9-]{1,40}$/;

/** Header names a profile may never claim: they are managed elsewhere. */
const RESERVED_HEADERS = Object.freeze(['host', 'content-length', 'transfer-encoding', 'connection']);

/** The SecretStorage key for a profile. Derived, never chosen by the caller. */
function secretKeyFor(profileId) {
  const id = String(profileId || '').trim();
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(id)) throw new Error('Identifiant de profil d’authentification invalide.');
  return `securityCenter.dynamic.auth.${id}`;
}

/**
 * Validates and normalizes a profile.
 *
 * Throws on anything that would produce an unusable or unsafe request. A profile
 * that carries a `value` is rejected outright: the credential must go to
 * SecretStorage, and accepting it here would be the first step to persisting it.
 */
function normalizeAuthProfile(input = {}) {
  const kind = String(input.kind || AUTH_KIND.NONE).toLowerCase();
  if (!Object.values(AUTH_KIND).includes(kind)) throw new Error(`Type d’authentification inconnu : ${kind}.`);
  if ('value' in input || 'token' in input || 'secret' in input || 'password' in input) {
    throw new Error('Un profil ne transporte jamais le secret : il est conservé dans le SecretStorage de VS Code.');
  }
  const id = String(input.id || '').trim() || 'default';
  secretKeyFor(id);
  const profile = {
    id,
    label: String(input.label || '').trim() || id,
    kind,
    // The header a credential will be sent in. Derived for the standard kinds so
    // a profile cannot claim `Host` or smuggle a second header.
    header: '',
    cookieName: '',
    status: Object.values(AUTH_STATUS).includes(input.status) ? input.status : AUTH_STATUS.NOT_CONFIGURED,
    lastValidatedAt: input.lastValidatedAt ? String(input.lastValidatedAt) : null,
    // Presence only: the value itself is never here.
    secretConfigured: input.secretConfigured === true,
    maskedValue: input.maskedValue ? String(input.maskedValue) : ''
  };
  if (kind === AUTH_KIND.BEARER) profile.header = 'Authorization';
  if (kind === AUTH_KIND.COOKIE) {
    profile.header = 'Cookie';
    profile.cookieName = String(input.cookieName || 'session').trim();
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(profile.cookieName)) throw new Error('Nom de cookie de session invalide.');
  }
  if (kind === AUTH_KIND.HEADER) {
    const header = String(input.header || '').trim();
    if (!ALLOWED_CUSTOM_HEADER.test(header)) throw new Error('Nom d’en-tête personnalisé invalide.');
    if (RESERVED_HEADERS.includes(header.toLowerCase())) throw new Error(`L’en-tête ${header} ne peut pas être défini par un profil.`);
    profile.header = header;
  }
  return profile;
}

/**
 * A displayable fingerprint of a credential.
 *
 * Enough to tell two tokens apart, not enough to reconstruct either: the first
 * four characters, the length, and nothing in between. A short secret shows
 * nothing at all rather than most of itself.
 */
function maskSecret(value) {
  const text = String(value || '');
  if (!text) return '';
  if (text.length < 12) return `••• (${text.length} caractères)`;
  return `${text.slice(0, 4)}…••• (${text.length} caractères)`;
}

/**
 * The request headers a profile contributes.
 *
 * The only place a credential is ever combined with a profile, and the result is
 * meant to be handed straight to a request — never logged, never stored, never
 * returned into a model. Returns `{}` when the secret is absent, so a
 * misconfigured profile produces an anonymous request rather than a broken one.
 */
function authHeadersFor(profile, secret) {
  const value = String(secret || '');
  if (!profile || profile.kind === AUTH_KIND.NONE || !value) return {};
  if (profile.kind === AUTH_KIND.BEARER) {
    // A token already carrying its scheme is not prefixed twice.
    return { Authorization: /^bearer\s/i.test(value) ? value : `Bearer ${value}` };
  }
  if (profile.kind === AUTH_KIND.COOKIE) {
    return { Cookie: value.includes('=') ? value : `${profile.cookieName || 'session'}=${value}` };
  }
  if (profile.kind === AUTH_KIND.HEADER && profile.header) return { [profile.header]: value };
  return {};
}

/**
 * Interprets a validation response.
 *
 * A 401 or 403 on an endpoint that previously authenticated means the credential
 * no longer works — `EXPIRED` when we had seen it work before, `INVALID` when we
 * never did. A 2xx is the only thing that establishes `VALID`; anything else
 * leaves the status `UNKNOWN` rather than guessing.
 */
function interpretValidation({ status = null, previousStatus = AUTH_STATUS.NOT_CONFIGURED, error = '' } = {}) {
  if (error) return { status: AUTH_STATUS.UNKNOWN, reason: 'La validation n’a pas abouti.' };
  const code = Number(status);
  if (!Number.isFinite(code)) return { status: AUTH_STATUS.UNKNOWN, reason: 'Aucune réponse exploitable.' };
  if (code >= 200 && code < 300) return { status: AUTH_STATUS.VALID, reason: `Réponse ${code} — session acceptée.` };
  if (code === 401 || code === 403) {
    const expired = previousStatus === AUTH_STATUS.VALID;
    return {
      status: expired ? AUTH_STATUS.EXPIRED : AUTH_STATUS.INVALID,
      reason: expired ? `Réponse ${code} — la session précédemment valide ne l’est plus.` : `Réponse ${code} — authentification refusée.`
    };
  }
  return { status: AUTH_STATUS.UNKNOWN, reason: `Réponse ${code} — non concluante pour l’authentification.` };
}

/**
 * Whether a scan may be described as authenticated.
 *
 * A configured token is not authenticated coverage. Only a profile whose session
 * was actually validated, and at least one protected endpoint really reached,
 * justifies the claim.
 */
function authenticatedCoverageClaim({ profile = null, validated = false, protectedEndpointsReached = 0 } = {}) {
  if (!profile || profile.kind === AUTH_KIND.NONE || !profile.secretConfigured) {
    return { authenticated: false, reason: 'Aucun profil d’authentification actif : le scan est anonyme.' };
  }
  if (!validated) {
    return { authenticated: false, reason: 'Le profil est configuré mais sa session n’a pas été validée : la couverture authentifiée n’est pas revendiquée.' };
  }
  if (!protectedEndpointsReached) {
    return { authenticated: false, reason: 'Session valide, mais aucun endpoint protégé n’a été atteint.' };
  }
  return {
    authenticated: true,
    reason: `Session validée et ${protectedEndpointsReached} endpoint(s) protégé(s) atteint(s).`
  };
}

/**
 * A profile as it may safely be persisted or rendered. Never carries a secret.
 *
 * Credential-shaped keys are *removed*, not set to `undefined`: the guard in
 * `normalizeAuthProfile` tests key presence, so blanking them would still trip it
 * — and, more importantly, a key present with an undefined value is exactly the
 * shape that survives a `JSON.parse(JSON.stringify(...))` round trip unnoticed.
 */
function publicProfile(profile) {
  const { value, token, secret, password, ...safe } = profile || {};
  const normalized = normalizeAuthProfile(safe);
  return {
    id: normalized.id,
    label: normalized.label,
    kind: normalized.kind,
    header: normalized.header,
    cookieName: normalized.cookieName,
    status: normalized.status,
    statusLabel: AUTH_STATUS_LABELS[normalized.status],
    lastValidatedAt: normalized.lastValidatedAt,
    secretConfigured: normalized.secretConfigured,
    maskedValue: normalized.maskedValue
  };
}

module.exports = {
  AUTH_KIND, AUTH_STATUS, AUTH_STATUS_LABELS, RESERVED_HEADERS, ALLOWED_CUSTOM_HEADER,
  secretKeyFor, normalizeAuthProfile, maskSecret, authHeadersFor,
  interpretValidation, authenticatedCoverageClaim, publicProfile
};
