const { availability } = require('./dynamic-runtime');

/**
 * Les deux moteurs ZAP, et ce que la carte en dit.
 *
 * ZAP s'exécute par une installation locale — qui exige Java — ou par le moteur
 * Docker. Ce sont des **alternatives** : un seul utilisable suffit. Les traiter
 * comme des prérequis cumulatifs affichait « INDISPONIBLE — Prérequis manquant :
 * Moteur Docker » devant un ZAP local installé, prêt à tourner.
 */

/**
 * Le moteur qui va réellement s'exécuter.
 *
 * `auto` prend celui qui est disponible. Un moteur nommé dans
 * `security-center.yml` est respecté tant qu'il est utilisable ; s'il ne l'est
 * pas alors que l'autre l'est, la substitution est faite et **dite**, plutôt que
 * de refuser un scan qu'un moteur présent sait exécuter. Si aucun des deux n'est
 * utilisable, le moteur demandé est conservé : c'est `runZap` qui dira l'échec
 * réel, avec sa propre raison, au lieu qu'on la devine ici.
 */
function zapEngineChoice(configured, { localUsable = false, dockerUsable = false } = {}) {
  const wanted = String(configured || 'auto').trim().toLowerCase();
  const usable = { local: localUsable === true, docker: dockerUsable === true };
  const available = usable.local ? 'local' : usable.docker ? 'docker' : '';
  if (wanted === 'local' || wanted === 'docker') {
    if (usable[wanted]) return { engine: wanted, requested: wanted, substituted: false };
    if (available) return { engine: available, requested: wanted, substituted: true };
    return { engine: wanted, requested: wanted, substituted: false };
  }
  return { engine: available || 'auto', requested: 'auto', substituted: false };
}

/** L'étiquette qu'une carte affiche pour un moteur ZAP. */
function zapEngineLabel(engine) {
  const value = String(engine || '').trim().toLowerCase();
  if (value === 'local') return 'Local';
  if (value === 'docker') return 'Docker';
  return '';
}

/**
 * La disponibilité ZAP, à partir de ce que chaque moteur a répondu.
 *
 * Rien n'est déduit d'un historique de scans : un ZAP installé et jamais lancé
 * est disponible. Quand aucun moteur ne l'est, la raison nomme les deux chemins
 * au lieu d'un « indisponible » sans issue.
 */
function zapAvailabilityFrom(detected, configuredEngine = 'auto') {
  const localUsable = detected?.localUsable === true;
  const dockerUsable = detected?.dockerUsable === true;
  const localPath = String(detected?.localPath || '');
  const dockerVersion = String(detected?.dockerVersion || '');
  const hasJava = detected?.hasJava === true;
  const javaVersion = String(detected?.javaVersion || '');
  const javaWarning = String(detected?.javaWarning || '');
  const javaReason = String(detected?.javaReason || '');
  // Le moteur annoncé est celui qui s'exécutera : la carte ne promet pas
  // « Local ou Docker » quand le choix est déjà tranché.
  const choice = zapEngineChoice(configuredEngine, { localUsable, dockerUsable });
  const engineDetail = choice.engine === 'local' && localUsable
    ? `Moteur Local · ${localPath}`
    : choice.engine === 'docker' && dockerUsable
      ? `Moteur Docker ${dockerVersion}`
      : '';
  return availability({
    installed: localUsable || dockerUsable,
    version: localUsable ? 'local' : dockerUsable ? `docker ${dockerVersion}` : '',
    executable: localUsable ? localPath : '',
    alternatives: [
      {
        name: 'ZAP local',
        satisfied: localUsable,
        detail: localPath
          ? hasJava
            ? `${localPath}${javaVersion ? ` · Java ${javaVersion}` : ''}`
            : `Java indisponible${javaReason ? ` : ${javaReason}` : ''}`
          : 'Aucune installation locale détectée'
      },
      { name: 'Moteur Docker', satisfied: dockerUsable, detail: dockerUsable ? `Docker ${dockerVersion}` : 'Moteur Docker indisponible' }
    ],
    detail: [engineDetail, javaWarning].filter(Boolean).join(' · '),
    // Une raison qui nomme les deux chemins sans dire lequel manque envoyait
    // installer un ZAP déjà installé. Ce qui est dit ici est ce qui a été observé.
    reason: localUsable || dockerUsable
      ? ''
      : localPath && !hasJava
        ? `ZAP local est installé (${localPath}) mais Java n’a pas répondu${javaReason ? ` : ${javaReason}` : '.'} Installez Java 17 ou supérieur, ou démarrez Docker Desktop.`
        : !localPath && hasJava
          ? `Java est disponible${javaVersion ? ` (${javaVersion})` : ''} mais aucune installation ZAP locale n’a été détectée. Installez OWASP ZAP, ou démarrez Docker Desktop.`
          : 'Ni ZAP local (avec Java) ni le moteur Docker ne sont disponibles. Installez ZAP et Java 17, ou démarrez Docker Desktop.',
    checkedAt: new Date().toISOString()
  });
}

/**
 * Les étapes ZAP, telles qu'une carte les annonce.
 *
 * Ce sont les états que ZAP publie lui-même — spider, file passive, scan actif,
 * collecte. Quand l'un d'eux n'a pas de pourcentage, l'étape est dite seule :
 * une progression inventée mentirait sur ce qui se passe.
 */
const ZAP_PHASE_LABEL = Object.freeze({
  STARTING: 'Preparing',
  SPIDERING: 'Spidering / baseline',
  PASSIVE_WAIT: 'Passive analysis',
  ACTIVE_SCANNING: 'Active scanning',
  COLLECTING_RESULTS: 'Collecting alerts'
});

/** La phase lisible d'une observation ZAP, moteur compris. */
function zapPhaseText(event, engineLabel = '') {
  const label = ZAP_PHASE_LABEL[String(event?.state || '')] || '';
  if (!label) return '';
  const percent = Number(event?.progress);
  const progress = event?.progress === null || event?.progress === undefined || event?.progress === '' || !Number.isFinite(percent)
    ? ''
    : ` ${Math.round(percent)} %`;
  const detail = event?.detail ? ` · ${event.detail}` : '';
  return `${engineLabel ? `Moteur ${engineLabel} · ` : ''}${label}${progress}${detail}`;
}

module.exports = { zapEngineChoice, zapEngineLabel, zapAvailabilityFrom, zapPhaseText, ZAP_PHASE_LABEL };
