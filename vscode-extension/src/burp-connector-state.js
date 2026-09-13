'use strict';

/**
 * Pourquoi le connecteur Burp n'alimente pas Security Center, en une raison.
 *
 * « Déconnecté » ne disait rien de ce qu'il fallait corriger : un backend
 * arrêté, une clé refusée, un connecteur jamais chargé et une capture rejetée
 * appellent quatre gestes différents. La raison est dérivée du statut que le
 * backend publie — heartbeat, refus de clé, dernière ingestion — ou de
 * l'impossibilité même de le lire. Le module est pur.
 */

const { RUN_ERROR } = require('./dynamic-runtime');

function timeOf(value) {
  const ms = Date.parse(String(value || ''));
  return Number.isFinite(ms) ? ms : null;
}

function clock(value) {
  return new Date(value).toLocaleTimeString('fr-FR');
}

/**
 * La panne à afficher, ou `null` quand tout va bien.
 *
 * `status.backend_error` est posé par l'extension quand le statut lui-même n'a
 * pas pu être lu : c'est alors la seule chose vraie à dire.
 */
function burpConnectorProblem(status) {
  const state = status && typeof status === 'object' ? status : {};
  if (state.backend_error) {
    return {
      code: RUN_ERROR.BACKEND_UNAVAILABLE,
      reason: `Backend Security Center injoignable (${String(state.backend_error).slice(0, 160)}) : le connecteur Burp n’a nulle part où verser son trafic.`
    };
  }
  const connected = state.connected === true;
  const lastSeen = timeOf(state.last_seen);
  const rejectedAt = timeOf(state.last_auth_rejected_at);
  if (!connected && rejectedAt !== null && (lastSeen === null || rejectedAt > lastSeen)) {
    return {
      code: RUN_ERROR.AUTH_REJECTED,
      reason: `Clé API refusée à ${clock(rejectedAt)} : le connecteur Burp n’utilise pas la clé du backend actif. Dans Burp, onglet Security Center, cliquez « Recharger la configuration ».`
    };
  }
  const failure = state.last_ingestion_error && typeof state.last_ingestion_error === 'object' ? state.last_ingestion_error : null;
  const failedAt = timeOf(failure?.at);
  const ingestedAt = timeOf(state.last_ingested_at);
  if (failedAt !== null && (ingestedAt === null || failedAt > ingestedAt)) {
    const rejected = Number(failure.status) >= 400 && Number(failure.status) < 500;
    return {
      code: rejected ? RUN_ERROR.INGESTION_REJECTED : RUN_ERROR.INGESTION_FAILED,
      reason: `${rejected ? 'Requête Burp refusée' : 'Échec d’enregistrement d’une requête Burp'} à ${clock(failedAt)} : ${String(failure.detail || 'raison non fournie').slice(0, 200)}.`
    };
  }
  if (!connected) {
    return {
      code: RUN_ERROR.CONNECTOR_ABSENT,
      reason: lastSeen !== null
        ? `Aucun battement du connecteur Burp depuis ${clock(lastSeen)}.`
        : 'Aucun battement du connecteur Burp reçu. Chargez l’extension SCenter dans Burp.'
    };
  }
  return null;
}

module.exports = { burpConnectorProblem };
