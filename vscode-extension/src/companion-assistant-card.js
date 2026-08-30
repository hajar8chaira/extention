'use strict';

/**
 * La carte « Companion Assistant » du rail de contexte.
 *
 * PRESENTATION UNIQUEMENT. Ce module ne lance aucun scanner, ne modifie aucun
 * finding, n'ecrit rien, n'appelle aucun modele et n'enregistre aucune commande.
 * Il prend des faits deja calcules ailleurs (le modele visuel partage du
 * companion, un finding, la liste des findings, l'etat du scan, l'etat du
 * pipeline) et decide comment les montrer.
 *
 * Trois regles gouvernent tout ce fichier :
 *
 *   1. AUCUN FAIT INVENTE. Une phrase n'est produite que si la donnee qui la
 *      soutient est reellement presente. Quand rien n'est connu,
 *      `buildAssistantCardModel` renvoie `null` et la carte ne s'affiche pas du
 *      tout — un assistant sans etat vaut mieux qu'un assistant qui devine.
 *
 *   2. AUCUNE COMMANDE NOUVELLE. Chaque action cite soit une commande deja
 *      enregistree par l'extension, soit un type de message webview deja traite
 *      par la page hote. Le catalogue ci-dessous est la liste exhaustive, et les
 *      tests verifient qu'il ne contient rien d'autre.
 *
 *   3. AUCUNE SORTIE BRUTE DE SCANNER. La carte ne rend que des chaines qu'elle
 *      compose elle-meme, plus le nom de fichier (sans chemin) du finding
 *      courant. Ni preuve, ni extrait de code, ni description d'outil, ni
 *      correctif : ces champs peuvent porter un secret detecte, et ils ne
 *      traversent jamais ce module.
 */

const { escapeHtml } = require('./security-center-shell');
const { renderMascotSvg, mascotCss } = require('./live/companionMascot');
const { VERIFICATION_STATE } = require('./fix-verification');

/**
 * Champs d'un finding qui peuvent contenir la valeur detectee elle-meme, un
 * extrait de source ou du texte brut d'outil. Ils sont nommes ici pour que le
 * test de non-divulgation ait une liste a verifier, et ils ne sont lus nulle
 * part dans ce fichier.
 */
const SENSITIVE_FINDING_FIELDS = Object.freeze([
  'evidence', 'originalText', 'autofix', 'secret', 'match', 'description',
  'solution', 'technicalDetails', 'fingerprint', 'commit', 'title'
]);

/**
 * Actions par commande : chacune est une commande DEJA enregistree par
 * `extension.js` et deja autorisee par la frontiere de confiance des pages qui
 * hebergent le rail (`allowed` du dashboard, `navCommands()` pour le cadre).
 * Toutes s'appellent sans argument.
 */
const COMMAND_ACTIONS = Object.freeze({
  'show-similar': { label: 'Montre-moi', command: 'securityCenter.openFindingsPage' },
  'review-finding': { label: 'Revoir le finding', command: 'securityCenter.openFindingsPage' },
  'verify-fix': { label: 'Vérifier la correction', command: 'securityCenter.verifyFindingFix' },
  'open-live': { label: 'Ouvrir Live Security', command: 'securityCenter.openLiveSecurityPage' },
  'open-pipeline': { label: 'Ouvrir le pipeline', command: 'securityCenter.openSecurityPipeline' },
  'open-scans': { label: 'Voir les scanners', command: 'securityCenter.openScansPage' },
  'configure-ollama': { label: 'Configurer Ollama', command: 'securityCenter.configureOllama' }
});

/**
 * Actions par message webview : chaque `post.type` est un type que la page hote
 * traite DEJA, avant cette carte.
 *
 *   - `generateAiFix` et `verifyFix` sont traites par le panneau « details du
 *     finding » (extension.js), qui les relaie vers `securityCenter.generateAiFix`
 *     et `securityCenter.verifyFindingFix` avec le finding courant.
 *   - `findingCode` est traite par le dashboard, qui le relaie vers
 *     `securityCenter.openFindingCode` avec le finding d'indice donne.
 *
 * `hosts` dit sur quelles surfaces le handler existe reellement. Une action
 * n'est jamais proposee sur une surface qui ne saurait pas la recevoir : ce
 * serait un bouton mort, ou pire, la tentation d'ajouter un second handler.
 */
const POST_ACTIONS = Object.freeze({
  explain: { label: 'Expliquer', post: { type: 'generateAiFix' }, hosts: ['finding-details'] },
  'verify-fix-current': { label: 'Vérifier la correction', post: { type: 'verifyFix' }, hosts: ['finding-details'] },
  'open-file': { label: 'Ouvrir le fichier', post: { type: 'findingCode' }, hosts: ['full', 'findings'], needsIndex: true },
  // Security Delivery : chaque `action` ci-dessous est deja traitee par le
  // panneau Security Delivery (`message.action === ...`). La carte n'ajoute
  // aucun handler, elle reutilise ceux du panneau.
  'delivery-gate': { label: 'Ouvrir le Policy Gate', post: { type: 'action', action: 'openBlocking' }, hosts: ['delivery'] },
  'delivery-report': { label: 'Voir le rapport', post: { type: 'action', action: 'openReport' }, hosts: ['delivery'] },
  'delivery-jenkinsfile': { label: 'Voir le Jenkinsfile', post: { type: 'action', action: 'openJenkinsfile' }, hosts: ['delivery'] },
  'delivery-test': { label: 'Tester la connexion', post: { type: 'action', action: 'testConnection' }, hosts: ['delivery'] },
  'delivery-refresh': { label: 'Actualiser l’état', post: { type: 'action', action: 'refresh' }, hosts: ['delivery'] }
});

/** Les seuls types de message que la carte peut emettre. Tous preexistants. */
const ASSISTANT_POST_TYPES = Object.freeze(['generateAiFix', 'verifyFix', 'findingCode', 'action', 'openCompanionChat']);

/**
 * Pour le type generique `action`, la liste fermee des actions autorisees.
 *
 * `action` est un type partage par plusieurs pages : le verifier seul ne dirait
 * pas grand-chose. Le relais controle donc aussi la valeur, et elle doit figurer
 * ici — chacune est un `data-action` que Security Delivery traite deja.
 */
const ASSISTANT_POST_ACTIONS = Object.freeze(['openBlocking', 'openReport', 'openJenkinsfile', 'testConnection', 'refresh']);

/**
 * Le lanceur d'intentions du bas de carte.
 *
 * Ce n'est PAS un chat : l'architecture actuelle n'a pas de conversation libre
 * avec Ollama (le fournisseur est appele par requete, pour un finding donne, via
 * `securityCenter.generateAiFix` / `securityCenter.explainLiveFinding` — aucun
 * historique, aucun contexte de session). Le champ du bas est donc une liste
 * fermee d'intentions, chacune resolue vers une action du catalogue ci-dessus.
 * Aucun texte libre n'est accepte, donc aucun texte libre n'est envoye nulle part.
 */
const ASSISTANT_INTENTS = Object.freeze([
  { id: 'explain-finding', label: 'Expliquer ce finding', actionId: 'explain' },
  { id: 'suggest-fix', label: 'Proposer une correction', actionId: 'explain' },
  { id: 'show-evidence', label: 'Montrer les preuves', actionId: 'review-finding' },
  { id: 'similar-findings', label: 'Findings similaires', actionId: 'show-similar' },
  { id: 'verify-fix', label: 'Vérifier la correction', actionId: 'verify-fix-current' },
  { id: 'verify-fix-any', label: 'Vérifier une correction', actionId: 'verify-fix' },
  { id: 'open-related-file', label: 'Ouvrir le fichier concerné', actionId: 'open-file' }
]);

/**
 * Conseil de securite : table locale et deterministe, indexee par CWE puis par
 * categorie. Rien n'est genere, rien n'est envoye a un service : le texte est
 * ecrit ici, en clair, et choisi par une simple correspondance.
 */
const TIPS_BY_CWE = Object.freeze({
  'CWE-89': 'Utilisez toujours des requêtes paramétrées pour les opérations de base de données.',
  'CWE-79': 'Échappez les données selon le contexte de sortie (HTML, attribut, URL) plutôt qu’une seule fois à l’entrée.',
  'CWE-78': 'Passez les arguments sous forme de tableau plutôt que de construire une ligne de commande shell.',
  'CWE-94': 'N’évaluez jamais à l’exécution du code construit à partir d’une donnée entrante.',
  'CWE-95': 'N’évaluez jamais à l’exécution du code construit à partir d’une donnée entrante.',
  'CWE-22': 'Résolvez le chemin final et vérifiez qu’il reste sous la racine autorisée avant d’ouvrir un fichier.',
  'CWE-798': 'Les secrets vivent dans une variable d’environnement ou un coffre, jamais dans le dépôt.',
  'CWE-259': 'Les secrets vivent dans une variable d’environnement ou un coffre, jamais dans le dépôt.',
  'CWE-295': 'Ne désactivez pas la vérification des certificats TLS, même en développement.',
  'CWE-327': 'Préférez un algorithme moderne (AES-GCM, SHA-256 ou plus) aux primitives dépréciées.',
  'CWE-326': 'Préférez un algorithme moderne (AES-GCM, SHA-256 ou plus) aux primitives dépréciées.',
  'CWE-352': 'Protégez les requêtes qui modifient un état par un jeton anti-CSRF vérifié côté serveur.',
  'CWE-1104': 'Suivez les versions de vos dépendances et mettez à jour celles qui portent une CVE connue.',
  'CWE-937': 'Suivez les versions de vos dépendances et mettez à jour celles qui portent une CVE connue.',
  'CWE-502': 'Ne désérialisez que des formats de données, jamais des objets arbitraires venant du réseau.',
  'CWE-611': 'Désactivez la résolution des entités externes dans votre parseur XML.'
});

const TIPS_BY_CATEGORY = Object.freeze({
  secret: 'Les secrets vivent dans une variable d’environnement ou un coffre, jamais dans le dépôt.',
  injection: 'Utilisez toujours des requêtes paramétrées pour les opérations de base de données.',
  crypto: 'Préférez un algorithme moderne (AES-GCM, SHA-256 ou plus) aux primitives dépréciées.',
  dependency: 'Suivez les versions de vos dépendances et mettez à jour celles qui portent une CVE connue.',
  vulnerability: 'Suivez les versions de vos dépendances et mettez à jour celles qui portent une CVE connue.',
  license: 'Vérifiez la compatibilité des licences de vos dépendances avant la mise en production.',
  security: 'Validez les entrées au plus près de leur usage, et pas seulement à la frontière de l’application.'
});

const DEFAULT_SECURITY_TIP = Object.freeze({
  text: 'Keep dependencies patched and review high-severity findings before merging.',
  source: 'default'
});

/**
 * Etats de remediation qui meritent la ligne principale de la carte.
 *
 * `new` en est volontairement absent : « cette alerte est nouvelle » n'apprend
 * rien au developpeur qui vient de l'ouvrir, et laisse la place a un fait plus
 * utile (findings similaires, atteignabilite, densite du fichier).
 */
const FIX_MESSAGES = Object.freeze({
  [VERIFICATION_STATE.FIX_PROPOSED]: { text: 'Une correction est proposée et attend votre décision.', tone: 'attention' },
  [VERIFICATION_STATE.FIX_APPLIED]: { text: 'Une correction a été appliquée et attend sa vérification.', tone: 'attention' },
  [VERIFICATION_STATE.VALIDATING]: { text: 'La vérification de la correction est en cours.', tone: 'neutral' },
  [VERIFICATION_STATE.VALIDATED]: { text: 'L’absence de cette vulnérabilité a été confirmée par un nouveau scan.', tone: 'good' },
  [VERIFICATION_STATE.STILL_PRESENT]: { text: 'Cette vulnérabilité est toujours présente après vérification.', tone: 'alert' },
  [VERIFICATION_STATE.VALIDATION_FAILED]: { text: 'La vérification n’a pas pu aboutir : le scanner n’a pas rendu de verdict.', tone: 'attention' },
  [VERIFICATION_STATE.INCONCLUSIVE]: { text: 'La vérification n’est pas concluante : le résultat ne tranche pas.', tone: 'attention' },
  [VERIFICATION_STATE.REGRESSED]: { text: 'Cette vulnérabilité est réapparue après avoir été validée.', tone: 'alert' }
});

/** Statuts d'atteignabilite qui portent une affirmation, avec leur formulation. */
const REACHABILITY_MESSAGES = Object.freeze({
  REACHABLE: { text: 'Ce finding est atteignable depuis une entrée de l’application.', tone: 'alert' },
  statically_reachable: { text: 'Ce finding est atteignable depuis une entrée de l’application.', tone: 'alert' },
  dynamically_confirmed: { text: 'L’atteignabilité de ce finding a été confirmée dynamiquement.', tone: 'alert' },
  POTENTIALLY_REACHABLE: { text: 'Ce finding est potentiellement atteignable.', tone: 'attention' },
  NOT_REACHABLE: { text: 'Ce finding n’est pas atteignable depuis le code exécuté.', tone: 'good' },
  not_reachable: { text: 'Ce finding n’est pas atteignable depuis le code exécuté.', tone: 'good' }
});

/** Ton du message → posture de la mascotte, dans le vocabulaire existant. */
const TONE_TO_MASCOT = Object.freeze({
  alert: 'warning', attention: 'watching', neutral: 'watching', good: 'success'
});

/** Nom de fichier seul : un chemin complet expose l'arborescence du poste. */
function baseName(value) {
  return String(value || '').replaceAll('\\', '/').split('/').filter(Boolean).pop() || '';
}

/** Un finding encore ouvert, au sens du cycle de vie deja en place. */
function isActive(finding) {
  const status = String(finding?.triageStatus || finding?.verification?.state || '').toLowerCase();
  return !['validated', 'false_positive', 'accepted'].includes(status);
}

/** L'etat de remediation reellement porte par le finding, ou ''. */
function fixStateOf(finding) {
  return String(finding?.verification?.state || finding?.triageStatus || '');
}

/** Identite d'un finding, pour ne pas compter deux fois le meme. */
function identityOf(finding) {
  return String(finding?.id || `${finding?.ruleId || ''}|${finding?.file || ''}|${finding?.startLine ?? ''}`);
}

/**
 * Le conseil de securite, derive du CWE puis de la categorie du finding courant.
 * Renvoie `null` quand rien ne correspond : mieux vaut pas de conseil qu'un
 * conseil generique presente comme contextuel.
 */
function securityTipFor(finding) {
  if (!finding) return null;
  const cwes = String(finding.cwe || '').toUpperCase().match(/CWE-\d+/g) || [];
  for (const cwe of cwes) {
    if (TIPS_BY_CWE[cwe]) return { text: TIPS_BY_CWE[cwe], source: cwe };
  }
  const category = String(finding.category || '').toLowerCase();
  for (const [key, text] of Object.entries(TIPS_BY_CATEGORY)) {
    if (category.includes(key)) return { text, source: category };
  }
  return null;
}

/** Repartition « 2 Critical · 1 High », composee ici, jamais lue d'un outil. */
function severityRollup(findings) {
  const counts = {};
  for (const finding of findings) {
    const key = String(finding.rawSeverity || finding.severity || 'unknown').toUpperCase();
    counts[key] = (counts[key] || 0) + 1;
  }
  const order = ['CRITICAL', 'ERROR', 'HIGH', 'MEDIUM', 'WARNING', 'LOW', 'INFO', 'INFORMATION'];
  const rank = (value) => (order.indexOf(value) === -1 ? order.length : order.indexOf(value));
  return Object.entries(counts)
    .sort((left, right) => rank(left[0]) - rank(right[0]))
    .slice(0, 3)
    .map(([severity, count]) => `${count} ${severity[0]}${severity.slice(1).toLowerCase()}`)
    .join(' · ');
}

function severityRank(value) {
  return { critical: 5, error: 5, high: 4, medium: 3, warning: 3, low: 2, info: 1, information: 1 }[String(value || '').toLowerCase()] || 0;
}

function highestSeverity(findings = []) {
  return [...findings]
    .sort((left, right) => severityRank(right.rawSeverity || right.severity) - severityRank(left.rawSeverity || left.severity))[0];
}

function compactCount(value) {
  return Number.isFinite(Number(value)) ? String(Number(value)) : '—';
}

function assistantStatusFor(companion = null, scan = null) {
  if (companion?.state) {
    const labels = {
      idle: 'Active',
      analyzing: 'Analyzing',
      clean: 'Clean',
      findings: 'Attention',
      degraded: 'Degraded',
      disabled: 'Off',
      error: 'Error'
    };
    return { label: labels[companion.state] || String(companion.state), scope: 'live' };
  }
  if (scan?.status) {
    const labels = {
      running: 'Running',
      completed: 'Completed',
      partial: 'Partial',
      cancelled: 'Cancelled',
      failed: 'Failed'
    };
    return { label: labels[scan.status] || String(scan.status), scope: 'scan' };
  }
  return null;
}

function fallbackSecurityTipFor({ surface = '', message = null } = {}) {
  if (!message && !surface) return null;
  return DEFAULT_SECURITY_TIP;
}

function assistantPanelMessageFor({ assistantMessage = null, heroMessage = null } = {}) {
  if (assistantMessage) return assistantMessage;
  if (!heroMessage) return null;
  if (heroMessage.tone === 'good') {
    return {
      text: 'No immediate action is required.',
      tone: 'good',
      source: 'assistant',
      scope: heroMessage.scope || ''
    };
  }
  if (heroMessage.source === 'scan' && heroMessage.scope === 'current-run') {
    return {
      text: 'Analysis is running. Current-run findings will appear as scanners complete.',
      tone: 'neutral',
      source: 'scan',
      scope: 'current-run'
    };
  }
  return null;
}

function scanFactFor(scan = null) {
  if (!scan?.status) return null;
  const status = String(scan.status);
  const done = Number(scan.completed);
  const total = Number(scan.total);
  const terminal = ['completed', 'partial', 'cancelled', 'failed'].includes(status);
  if (status === 'running' && Number.isFinite(done) && Number.isFinite(total) && total > 0) {
    return { label: 'Current scan', value: `${done}/${total}`, detail: 'completed', scope: 'current-run' };
  }
  if (terminal) return { label: 'Last scan', value: status, detail: 'status', scope: status === 'completed' ? 'last-completed-run' : 'current-run' };
  return { label: 'Current scan', value: status, detail: 'status', scope: 'current-run' };
}

function scannerHealthFact(scanners = []) {
  const list = Array.isArray(scanners) ? scanners : [];
  const failed = list.filter((scanner) => ['failed', 'cancelled'].includes(String(scanner?.status)));
  if (failed.length) {
    return {
      label: 'Scanner health',
      value: String(failed.length),
      detail: `${failed.length === 1 ? 'scanner degraded' : 'scanners degraded'}`,
      scope: 'scanner-state'
    };
  }
  return null;
}

function contextFactsFor({ companion = null, findings = [], scan = null, scanners = [], posture = null } = {}) {
  const facts = [];
  const safeFindings = Array.isArray(findings) ? findings : [];
  const file = companion?.currentFile || '';
  const liveCountKnown = companion && Number.isFinite(Number(companion.liveFindingCount));
  const liveCount = liveCountKnown ? Number(companion.liveFindingCount) : null;
  if (liveCountKnown) {
    facts.push({
      label: 'Live issues',
      value: compactCount(liveCount),
      detail: 'in file',
      scope: 'live-file'
    });
  }
  const liveSeverity = companion?.liveHighestSeverity || '';
  if (liveCount > 0 && liveSeverity) {
    facts.push({ label: 'Max severity', value: String(liveSeverity).toUpperCase(), detail: 'Live', scope: 'live-file', severity: liveSeverity });
  }
  if (file) facts.push({ label: 'Current file', value: baseName(file), detail: 'Live scope', scope: 'live-file' });
  const postureCount = Number.isFinite(Number(posture?.findingCount)) ? Number(posture.findingCount) : safeFindings.length;
  const postureLabel = posture?.label || (scan?.status === 'running' ? 'Current run' : 'Workspace posture');
  const scanRelevant = scan?.status === 'running' || ['failed', 'cancelled', 'partial'].includes(String(scan?.status || ''));
  const postureRelevant = !companion || scanRelevant || liveCount > 0;
  if (postureRelevant && (posture || safeFindings.length)) {
    const top = posture?.highestSeverity || (highestSeverity(safeFindings)?.rawSeverity || highestSeverity(safeFindings)?.severity || '');
    facts.push({
      label: postureLabel,
      value: compactCount(postureCount),
      detail: top ? `${String(top).toUpperCase()} highest` : 'findings',
      scope: posture?.scope || (scan?.status === 'running' ? 'current-run' : 'workspace-posture'),
      severity: top
    });
  }
  const scanFact = scanFactFor(scan);
  if (scanFact && scanRelevant) facts.push(scanFact);
  const health = scannerHealthFact(scanners);
  if (health) facts.push(health);
  return facts.slice(0, 3);
}

function heroMessageFor({ companion = null, findings = [], scan = null, scanners = [], fallback = null } = {}) {
  const file = baseName(companion?.currentFile || '');
  const liveCount = Number.isFinite(Number(companion?.liveFindingCount)) ? Number(companion.liveFindingCount) : null;
  const liveSeverity = String(companion?.liveHighestSeverity || '');
  if (liveCount !== null && liveCount > 0) {
    return {
      text: `I found ${liveCount} security issue${liveCount > 1 ? 's' : ''}${file ? ` in ${file}` : ''}.${liveSeverity ? ` Highest severity is ${liveSeverity}.` : ''}`,
      tone: ['critical', 'high', 'error'].includes(liveSeverity.toLowerCase()) ? 'alert' : 'attention',
      source: 'companion',
      scope: 'live-file'
    };
  }
  const degraded = scannerHealthFact(scanners);
  if (degraded && file) {
    return {
      text: `I'm still monitoring ${file}, but ${degraded.value} scanner${degraded.value === '1' ? '' : 's'} need attention.`,
      tone: 'attention',
      source: 'scanner-state',
      scope: 'scanner-state'
    };
  }
  if (scan?.status === 'running') {
    return {
      text: 'Security analysis is running. Current-run results will appear only after scanners finish.',
      tone: 'neutral',
      source: 'scan',
      scope: 'current-run'
    };
  }
  if (liveCount === 0) {
    return {
      text: file ? `I'm watching ${file}. No live issues are currently detected.` : 'Live Security is watching your current file.',
      tone: 'good',
      source: 'companion',
      scope: 'live-file'
    };
  }
  if (companion?.message?.headline || companion?.shortMessage) {
    return {
      text: String(companion.shortMessage || companion.message.headline),
      tone: 'neutral',
      source: 'companion',
      scope: 'live-file'
    };
  }
  return fallback || null;
}

function assistantMascotPresenceState({ companion = null, scan = null, scanners = [] } = {}) {
  const liveCount = Number.isFinite(Number(companion?.liveFindingCount)) ? Number(companion.liveFindingCount) : null;
  const liveSeverity = String(companion?.liveHighestSeverity || '').toLowerCase();
  const degraded = scannerHealthFact(scanners);
  if ((liveCount > 0 && ['critical', 'high', 'error'].includes(liveSeverity)) || degraded) return 'warning';

  const scanStatus = String(scan?.status || '').toLowerCase();
  const companionState = String(companion?.state || '').toLowerCase();
  const mascotState = String(companion?.mascotState || '').toLowerCase();
  if (scanStatus === 'running' || companionState === 'analyzing' || mascotState === 'thinking') return 'analyzing';

  if (liveCount === 0 && companion) return 'healthy';
  return 'idle';
}

/**
 * La phrase que la carte affiche, et d'ou elle vient.
 *
 * L'ordre est un classement d'utilite, pas une preference esthetique : ce que le
 * developpeur vient de faire (une correction) passe avant ce qu'il pourrait
 * decouvrir (des findings similaires), qui passe avant un resume de projet.
 *
 * `source` nomme le modele reel qui porte le fait. Il est expose dans le modele
 * et dans le DOM pour que la provenance soit verifiable, y compris par les tests.
 */
function assistantMessageFor({ surface = '', companion = null, finding = null, findings = [], scan = null, pipeline = null, delivery = null } = {}) {
  const list = Array.isArray(findings) ? findings : [];

  if (finding) {
    // 1. Le cycle de verification : le fait le plus recent et le plus actionnable.
    const fixState = fixStateOf(finding);
    if (FIX_MESSAGES[fixState]) {
      return { ...FIX_MESSAGES[fixState], source: 'fix-verification', fixState };
    }
    // 2. La meme regle ailleurs dans le workspace : un fait que seule la liste
    //    complete des findings connait, et que la page du finding n'affiche pas.
    if (finding.ruleId) {
      const identity = identityOf(finding);
      const similar = list.filter((candidate) => candidate.ruleId === finding.ruleId
        && identityOf(candidate) !== identity && isActive(candidate));
      if (similar.length) {
        return {
          text: `J’ai trouvé ${similar.length} finding${similar.length > 1 ? 's' : ''} similaire${similar.length > 1 ? 's' : ''} dans ce workspace.`,
          tone: 'attention', source: 'findings', count: similar.length
        };
      }
    }
    // 3. L'atteignabilite, quand le pipeline d'intelligence l'a reellement calculee.
    const reachability = finding.reachability?.status || finding.reachability?.state || '';
    if (REACHABILITY_MESSAGES[reachability]) {
      return { ...REACHABILITY_MESSAGES[reachability], source: 'intelligence', reachability };
    }
    // 4. La densite du fichier courant.
    if (finding.file) {
      const sameFile = list.filter((candidate) => candidate.file === finding.file && isActive(candidate));
      if (sameFile.length > 1) {
        return {
          text: `Ce fichier contient ${sameFile.length} findings actifs.`,
          tone: 'attention', source: 'findings', count: sameFile.length
        };
      }
    }
    return null;
  }

  // Security Delivery : l'etat du dernier build, tel que Jenkins et le rapport
  // archive le rapportent. Jamais le verdict du scan local — ce sont deux
  // identites de scan distinctes, et les melanger serait une affirmation fausse.
  if (surface === 'delivery' && delivery) {
    const connectionState = delivery.connection?.state || '';
    if (delivery.state === 'ERROR' || (connectionState && connectionState !== 'CONNECTED')) {
      return { text: 'Jenkins est injoignable : aucun état de livraison ne peut être lu.', tone: 'alert', source: 'jenkins' };
    }
    const report = delivery.ci?.report || null;
    // La correspondance du code passe avant le verdict : un gate vert qui porte
    // sur un autre commit n'est pas un gate vert pour le code ouvert ici.
    if (report && delivery.commit?.match === 'DIFFERENT') {
      return { text: 'Le verdict de ce build ne porte pas sur le code ouvert ici : le commit diffère.', tone: 'alert', source: 'jenkins' };
    }
    if (report) {
      const { critical, high } = report.summary;
      const risk = [critical ? `${critical} critique${critical > 1 ? 's' : ''}` : '', high ? `${high} élevé${high > 1 ? 's' : ''}` : '']
        .filter(Boolean).join(' et ');
      const status = String(report.policy.status).toUpperCase();
      if (status === 'BLOCK') {
        return { text: `La dernière livraison a été bloquée par le Policy Gate${risk ? ` — ${risk}` : ''}.`, tone: 'alert', source: 'jenkins' };
      }
      if (status === 'WARN') {
        return { text: `La dernière livraison a passé le Policy Gate avec réserves${risk ? ` — ${risk}` : ''}.`, tone: 'attention', source: 'jenkins' };
      }
      if (status === 'PASS') {
        return risk
          ? { text: `La dernière livraison a passé le Policy Gate avec ${risk}.`, tone: 'attention', source: 'jenkins' }
          : { text: 'La dernière livraison a passé le Policy Gate.', tone: 'good', source: 'jenkins' };
      }
      return { text: `Le Policy Gate de cette livraison est en état ${status}.`, tone: 'attention', source: 'jenkins' };
    }
    if (delivery.build) {
      return { text: 'Ce build n’a publié aucun rapport Security Center : son verdict de sécurité est inconnu.', tone: 'attention', source: 'jenkins' };
    }
    return { text: 'Le job est configuré mais n’a pas encore produit de build.', tone: 'neutral', source: 'jenkins' };
  }

  // Live Security : le fichier ouvert, decrit par le modele companion partage.
  if (surface === 'live' && companion) {
    const live = Number(companion.liveFindingCount) || 0;
    if (live > 0) {
      return {
        text: `Ce fichier contient ${live} avertissement${live > 1 ? 's' : ''} Live.`,
        tone: 'alert', source: 'companion', count: live
      };
    }
    const short = String(companion.shortMessage || companion.message?.headline || '');
    return short ? { text: short, tone: 'neutral', source: 'companion' } : null;
  }

  // Pipeline : l'etat de la porte de politique, tel que le pipeline l'a rendu.
  if (surface === 'pipeline' && pipeline) {
    const status = String(pipeline.policyStatus || '').toUpperCase();
    // Sur cette surface le gate juge LE SCAN, pas une livraison : parler de
    // « livraison » ici attribuerait le verdict a un build Jenkins, qui est une
    // autre identite de scan et vit sur Security Delivery.
    if (status === 'BLOCK') return { text: 'La politique projet bloque ce scan.', tone: 'alert', source: 'pipeline' };
    if (status === 'WARN') return { text: 'La politique projet signale des réserves sur ce scan.', tone: 'attention', source: 'pipeline' };
    if (status === 'PASS') return { text: 'La politique projet est respectée sur le dernier scan.', tone: 'good', source: 'pipeline' };
    const stage = String(pipeline.stage || '');
    return stage ? { text: `Étape courante du pipeline : ${stage}.`, tone: 'neutral', source: 'pipeline' } : null;
  }

  // Scans : l'avancement reel des scanners.
  if (surface === 'scans' && scan) {
    const status = String(scan.status || '');
    const done = Number(scan.completed);
    const total = Number(scan.total);
    if (status === 'running' && Number.isFinite(done) && Number.isFinite(total)) {
      return { text: `Analyse en cours : ${done}/${total} scanners terminés.`, tone: 'neutral', source: 'scan' };
    }
    if (status === 'failed') return { text: 'Le dernier scan s’est terminé en échec.', tone: 'alert', source: 'scan' };
    if (status === 'completed' && Number.isFinite(total)) {
      return { text: `Dernier scan terminé : ${total} scanner${total > 1 ? 's' : ''} exécuté${total > 1 ? 's' : ''}.`, tone: 'good', source: 'scan' };
    }
    return null;
  }

  // Dashboard et Findings : le resume du workspace, compose a partir de la liste
  // que la page affiche deja — jamais d'un total venu d'ailleurs.
  if (['full', 'findings'].includes(surface)) {
    const active = list.filter(isActive);
    if (active.length) {
      const rollup = severityRollup(active);
      return {
        text: `${active.length} alerte${active.length > 1 ? 's' : ''} active${active.length > 1 ? 's' : ''} dans ce workspace${rollup ? ` — ${rollup}` : ''}.`,
        tone: 'attention', source: 'findings', count: active.length
      };
    }
    if (list.length) return { text: 'Toutes les alertes de ce workspace sont traitées.', tone: 'good', source: 'findings' };
    if (scan && String(scan.status) === 'completed') {
      return { text: 'Le dernier scan n’a laissé aucune alerte active.', tone: 'good', source: 'scan' };
    }
    return null;
  }

  return null;
}

/**
 * Commande de navigation que chaque surface represente deja.
 *
 * Une action qui reouvre la page ouverte est un bouton qui ne fait rien de
 * visible : elle est retiree plutot que proposee.
 */
const SURFACE_SELF_COMMAND = Object.freeze({
  full: 'securityCenter.openDashboard',
  findings: 'securityCenter.openFindingsPage',
  scans: 'securityCenter.openScansPage',
  pipeline: 'securityCenter.openSecurityPipeline',
  live: 'securityCenter.openLiveSecurityPage',
  delivery: 'securityCenter.openSecurityDelivery'
});

/** Resout un identifiant d'action en action concrete, ou `null`. */
function resolveAction(id, { surface = '', findingIndex = null } = {}) {
  if (COMMAND_ACTIONS[id]) {
    if (COMMAND_ACTIONS[id].command === SURFACE_SELF_COMMAND[surface]) return null;
    return { id, ...COMMAND_ACTIONS[id] };
  }
  const post = POST_ACTIONS[id];
  if (!post) return null;
  if (!post.hosts.includes(surface)) return null;
  if (post.needsIndex && !Number.isInteger(findingIndex)) return null;
  return {
    id,
    label: post.label,
    post: post.needsIndex ? { ...post.post, index: findingIndex } : { ...post.post }
  };
}

/** Les actions candidates d'un message, dans l'ordre d'utilite. */
function actionIdsFor(message, { finding = null } = {}) {
  if (!message) return [];
  if (message.source === 'fix-verification') {
    return [VERIFICATION_STATE.VALIDATED, VERIFICATION_STATE.VALIDATING].includes(message.fixState)
      ? ['review-finding', 'explain']
      : ['verify-fix-current', 'verify-fix', 'explain'];
  }
  if (message.source === 'findings' && finding) return ['show-similar', 'explain', 'open-file'];
  if (message.source === 'intelligence') return ['explain', 'review-finding'];
  if (message.source === 'companion') return ['open-live', 'review-finding'];
  if (message.source === 'pipeline') return ['open-pipeline', 'review-finding'];
  if (message.source === 'scan') return ['open-scans', 'review-finding'];
  if (message.source === 'jenkins') {
    if (message.tone === 'alert') return ['delivery-gate', 'delivery-test', 'delivery-report'];
    return ['delivery-report', 'delivery-jenkinsfile', 'delivery-refresh'];
  }
  return ['show-similar', 'verify-fix'];
}

/** Nombre d'actions rendues, hors « Pas maintenant ». La carte reste compacte. */
const MAX_ACTIONS = 2;

/**
 * Le modele de la carte, ou `null`.
 *
 * `null` n'est pas un cas d'erreur : c'est la reponse correcte quand aucun fait
 * reel n'est disponible. La carte disparait alors entierement du rail.
 */
function buildAssistantCardModel({
  surface = '', companion = null, finding = null, findings = [], findingIndex = null,
  scan = null, scanners = [], pipeline = null, delivery = null, posture = null, enabled = true
} = {}) {
  if (!enabled) return null;
  const assistantMessage = assistantMessageFor({ surface, companion, finding, findings, scan, pipeline, delivery });
  const heroMessage = heroMessageFor({ companion, findings, scan, scanners, fallback: assistantMessage });
  if (!assistantMessage && !heroMessage) return null;
  const message = assistantMessage || heroMessage;

  const actions = actionIdsFor(message, { finding })
    .map((id) => resolveAction(id, { surface, findingIndex }))
    .filter(Boolean)
    .slice(0, MAX_ACTIONS);

  // Le lanceur ne propose que les intentions dont l'action existe reellement ici.
  const intents = ASSISTANT_INTENTS
    .map((intent) => {
      const action = resolveAction(intent.actionId, { surface, findingIndex });
      return action ? { ...intent, action } : null;
    })
    .filter(Boolean);

  // La posture vient du companion quand il en a une ; sinon du ton du message,
  // traduit dans le vocabulaire de mascotte deja en place. Aucun etat nouveau.
  const mascotState = companion?.mascotState || TONE_TO_MASCOT[message.tone] || 'idle';
  const mascotPresenceState = assistantMascotPresenceState({ companion, scan, scanners });
  const heroAction = (companion ? resolveAction('open-live', { surface, findingIndex }) : null) || actions[0] || null;
  const contextFacts = contextFactsFor({ companion, finding, findings, scan, scanners, posture });
  const liveCount = typeof companion?.liveFindingCount === 'number' ? companion.liveFindingCount : null;
  const panelMessage = companion && surface === 'full' && liveCount === 0 && assistantMessage?.source === 'findings'
    ? null
    : assistantPanelMessageFor({ assistantMessage, heroMessage });
  const tip = securityTipFor(finding) || fallbackSecurityTipFor({ surface, message: panelMessage || heroMessage });

  return {
    surface,
    mascotState,
    mascotPresenceState,
    message,
    heroMessage,
    heroAction: heroAction ? { ...heroAction, label: 'View details' } : null,
    actions,
    panelMessage,
    status: assistantStatusFor(companion, scan),
    contextFacts,
    tip,
    intents,
    file: baseName(finding?.file),
    placeholder: finding ? 'Poser une question sur ce finding…' : 'Demander à Security Center…'
  };
}

/** La charge utile d'un bouton : commande existante, ou message webview existant. */
function actionAttributes(action) {
  return action.post
    ? ` data-assistant-post="${escapeHtml(JSON.stringify(action.post))}"`
    : ` data-command="${escapeHtml(action.command)}"`;
}

function renderAction(action, className) {
  return `<button type="button" class="${className}"${actionAttributes(action)}>${escapeHtml(action.label)}</button>`;
}

function renderAssistantHeroCard(model, options = {}) {
  if (!model) return '';
  const message = model.heroMessage || model.message;
  const contextFacts = model.contextFacts || [];
  const presence = model.mascotPresenceState || 'idle';
  const mascotImageUri = options.mascotImageUri || model.mascotImageUri || '';
  return `<section class="sc-assistant sc-assistant-hero" data-assistant-surface="${escapeHtml(model.surface)}" aria-label="Live Security Companion">
    <div class="sc-assistant-head">
      <div><strong>Live Security Companion</strong>${model.status ? `<span class="sc-assistant-status" data-assistant-status-scope="${escapeHtml(model.status.scope)}">● ${escapeHtml(model.status.label)}</span>` : ''}</div>
      <button type="button" class="sc-assistant-collapse" aria-expanded="true" aria-label="Replier l’assistant">⌃</button>
    </div>
    <div class="sc-assistant-body">
      <div class="sc-assistant-talk">
        <span class="sc-assistant-mascot companion-state-${escapeHtml(presence)}" data-companion-visual-state="${escapeHtml(presence)}" aria-hidden="true">${renderMascotSvg(model.mascotState, 'Security Companion', { src: mascotImageUri })}</span>
        <div class="sc-assistant-bubble sc-tone-${escapeHtml(message.tone)}" role="status" aria-live="polite" data-assistant-source="${escapeHtml(message.source)}" data-assistant-scope="${escapeHtml(message.scope || '')}">
          <span>${escapeHtml(message.text)}</span>
          ${model.heroAction ? renderAction(model.heroAction, 'sc-assistant-action sc-assistant-hero-cta') : ''}
        </div>
      </div>
      ${contextFacts.length ? `<div class="sc-assistant-facts" aria-label="Companion context">
        ${contextFacts.map((fact) => `<div class="sc-assistant-fact" data-assistant-fact-scope="${escapeHtml(fact.scope || '')}">
          <strong class="${fact.severity ? `sc-assistant-sev ${escapeHtml(String(fact.severity).toLowerCase())}` : ''}">${escapeHtml(fact.value)}</strong>
          <span>${escapeHtml(fact.label)}</span>
          ${fact.detail ? `<small>${escapeHtml(fact.detail)}</small>` : ''}
        </div>`).join('')}
      </div>` : ''}
    </div>
  </section>`;
}

function renderAssistantPanelCard(model) {
  if (!model) return '';
  const message = Object.prototype.hasOwnProperty.call(model, 'panelMessage') ? model.panelMessage : model.message;
  const actions = message ? model.actions : [];
  const { tip, intents } = model;
  const options = intents
    .map((intent) => `<option value="${escapeHtml(intent.id)}">${escapeHtml(intent.label)}</option>`)
    .join('');
  const intentTargets = intents
    .map((intent) => `<button type="button" hidden class="sc-assistant-intent-target" data-assistant-intent="${escapeHtml(intent.id)}"${actionAttributes(intent.action)}></button>`)
    .join('');
  const hasPanelContent = message || actions.length || tip || intents.length;
  if (!hasPanelContent) return '';
  return `<section class="sc-assistant-panel" data-assistant-surface="${escapeHtml(model.surface)}" aria-label="Companion Assistant">
    <div class="sc-assistant-panel-head">
      <strong>Companion Assistant</strong>
      <button type="button" class="sc-assistant-collapse" aria-expanded="true" aria-label="Replier l’assistant">⌃</button>
    </div>
    <div class="sc-assistant-panel-body">
      ${message ? `<div class="sc-assistant-recommendation sc-tone-${escapeHtml(message.tone)}" role="status" aria-live="polite" data-assistant-source="${escapeHtml(message.source)}" data-assistant-scope="${escapeHtml(message.scope || '')}"><span>${escapeHtml(message.text)}</span></div>` : ''}
      ${actions.length ? `<div class="sc-assistant-actions">
        ${actions.map((action, index) => renderAction(action, index === 0 ? 'sc-assistant-action primary' : 'sc-assistant-action')).join('')}
        <button type="button" class="sc-assistant-action sc-assistant-dismiss">Pas maintenant</button>
      </div>` : ''}
      ${tip ? `<div class="sc-assistant-tip" data-assistant-tip-source="${escapeHtml(tip.source)}">
        <strong><span aria-hidden="true">💡</span> Security Tip</strong>
        <span>${escapeHtml(tip.text)}</span>
      </div>` : ''}
      <div class="sc-assistant-open">
        <button type="button" class="sc-assistant-openchat" data-assistant-post='{"type":"openCompanionChat"}'>Ouvrir la conversation →</button>
      </div>
      ${intents.length ? `<div class="sc-assistant-ask">
        <label class="sc-assistant-sr" for="sc-assistant-intent">${escapeHtml(model.placeholder)}</label>
        <select id="sc-assistant-intent" class="sc-assistant-intent">
          <option value="" selected>${escapeHtml(model.placeholder)}</option>
          ${options}
        </select>
        <button type="button" class="sc-assistant-send" aria-label="Lancer l’action choisie">➤</button>
        ${intentTargets}
      </div>` : ''}
    </div>
  </section>`;
}

/**
 * La carte.
 *
 * Un modele absent ne rend rien du tout — pas un cadre vide, pas un squelette.
 */
function renderAssistantCard(model, options = {}) {
  if (!model) return '';
  return `<div class="sc-assistant-stack">${renderAssistantHeroCard(model, options)}${renderAssistantPanelCard(model)}</div>`;
}

/**
 * La feuille de style de la carte.
 *
 * Uniquement des tokens `--sc-*` deja definis par le cadre (`shellTokensCss`) et
 * par le dashboard : la carte ne declare aucune couleur en dur, donc elle suit
 * les deux themes sans regle propre au theme sombre.
 *
 * La feuille de la mascotte est incluse : la carte apparait sur des pages qui
 * n'hebergent pas forcement le widget flottant, et sans elle le personnage y
 * sortirait sans couleur. Les regles etant identiques a celles du widget, les
 * pages qui portent les deux ne subissent qu'une repetition inoffensive.
 */
function assistantCardCss() {
  return `${mascotCss()}
    .sc-assistant-stack { display: grid; gap: 12px; }
    .sc-assistant { display: grid; gap: 0; padding: 13px; border: 1px solid color-mix(in srgb, var(--sc-primary) 22%, var(--sc-border)); border-radius: var(--sc-radius-lg); color: var(--vscode-button-foreground, #fff); background: linear-gradient(145deg, var(--sc-primary), color-mix(in srgb, var(--sc-primary) 74%, var(--sc-surface))); box-shadow: var(--sc-shadow-sm); overflow: hidden; }
    .sc-assistant-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .sc-assistant-head > div { display: grid; gap: 3px; min-width: 0; }
    .sc-assistant-head strong { color: currentColor; font-size: 11px; }
    .sc-assistant-status { color: color-mix(in srgb, currentColor 86%, transparent); font-size: 8px; font-weight: 800; letter-spacing: .3px; text-transform: uppercase; }
    .sc-assistant-collapse { padding: 0 4px; border: 0; border-radius: var(--sc-radius-sm); color: currentColor; background: transparent; font: inherit; line-height: 1; cursor: pointer; opacity: .78; }
    .sc-assistant-collapse:hover { opacity: 1; background: color-mix(in srgb, currentColor 14%, transparent); }
    .sc-assistant[data-collapsed="true"] .sc-assistant-body { display: none; }
    .sc-assistant[data-collapsed="true"] .sc-assistant-collapse { transform: rotate(180deg); }
    .sc-assistant-panel[data-collapsed="true"] .sc-assistant-panel-body { display: none; }
    .sc-assistant-panel[data-collapsed="true"] .sc-assistant-collapse { transform: rotate(180deg); }
    .sc-assistant-body { display: grid; gap: 11px; margin-top: 12px; }
    /* Mascotte a gauche, bulle a droite : l'axe de lecture de la carte. */
    .sc-assistant-talk { display: grid; grid-template-columns: minmax(82px, 36%) minmax(0, 1fr); align-items: center; gap: 11px; }
    .sc-assistant-mascot { position: relative; display: grid; place-items: center; min-height: 112px; line-height: 0; transform-origin: 50% 78%; animation: sc-companion-float 5.2s ease-in-out infinite; }
    .sc-assistant-mascot::before { content: ''; position: absolute; z-index: 0; inset: 13px 6px 12px; border-radius: 999px; background: radial-gradient(circle, color-mix(in srgb, currentColor 20%, transparent), transparent 66%); opacity: .58; filter: blur(2px); transform: scale(.92); animation: sc-companion-glow 4.8s ease-in-out infinite; }
    .sc-assistant-mascot::after { content: ''; position: absolute; z-index: 1; width: 82px; height: 82px; border: 1px solid color-mix(in srgb, currentColor 30%, transparent); border-top-color: currentColor; border-radius: 50%; opacity: 0; transform: rotate(0deg); }
    .sc-assistant-mascot .mascot { position: relative; z-index: 2; width: 86px; height: 108px; max-width: 100%; filter: drop-shadow(0 10px 18px color-mix(in srgb, var(--sc-text) 20%, transparent)) drop-shadow(0 0 18px color-mix(in srgb, currentColor 22%, transparent)); transform-origin: 50% 78%; }
    .sc-assistant-mascot.companion-state-idle { animation-name: sc-companion-float; }
    .sc-assistant-mascot.companion-state-healthy { animation: sc-companion-float 5.8s ease-in-out infinite; }
    .sc-assistant-mascot.companion-state-healthy::before { opacity: .7; animation-name: sc-companion-soft-pulse; }
    .sc-assistant-mascot.companion-state-analyzing { animation: sc-companion-analyze 2.6s ease-in-out infinite; }
    .sc-assistant-mascot.companion-state-analyzing::before { opacity: .82; animation: sc-companion-glow 2.2s ease-in-out infinite; }
    .sc-assistant-mascot.companion-state-analyzing::after { opacity: .66; animation: sc-companion-scan-ring 2.4s linear infinite; }
    .sc-assistant-mascot.companion-state-warning { animation: sc-companion-attend 2.9s ease-in-out infinite; }
    .sc-assistant-mascot.companion-state-warning::before { opacity: .76; animation: sc-companion-warning-glow 2.6s ease-in-out infinite; }
    .sc-assistant-mascot.companion-state-warning::after { opacity: .42; border-top-color: var(--sc-medium); animation: sc-companion-warning-ring 3.2s ease-in-out infinite; }
    .sc-assistant-bubble { position: relative; display: grid; gap: 8px; margin: 0; padding: 10px 11px; border: 1px solid color-mix(in srgb, currentColor 36%, transparent); border-radius: var(--sc-radius-md); color: var(--sc-text); background: color-mix(in srgb, var(--sc-surface) 94%, transparent); font-size: 10.5px; line-height: 1.45; overflow-wrap: anywhere; box-shadow: 0 8px 18px color-mix(in srgb, var(--sc-text) 10%, transparent); }
    .sc-assistant-bubble span { display: -webkit-box; -webkit-line-clamp: 4; -webkit-box-orient: vertical; overflow: hidden; }
    /* La fleche pointe la mascotte : les deux blocs forment une reponse, pas
       deux elements empiles. */
    .sc-assistant-bubble::before { content: ''; position: absolute; top: 18px; left: -5px; width: 9px; height: 9px; border-left: 1px solid color-mix(in srgb, currentColor 36%, transparent); border-bottom: 1px solid color-mix(in srgb, currentColor 36%, transparent); background: color-mix(in srgb, var(--sc-surface) 94%, transparent); transform: rotate(45deg); }
    /* La severite passe par la bordure ET par la posture de la mascotte : jamais
       par la couleur seule. */
    .sc-assistant-bubble.sc-tone-alert { border-color: var(--sc-critical); }
    .sc-assistant-bubble.sc-tone-attention { border-color: var(--sc-medium); }
    .sc-assistant-bubble.sc-tone-good { border-color: var(--sc-low); }
    .sc-assistant-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; padding-top: 2px; }
    .sc-assistant-fact { min-width: 0; padding: 0; border: 0; border-radius: 0; background: transparent; color: currentColor; text-align: center; }
    .sc-assistant-fact span, .sc-assistant-fact strong, .sc-assistant-fact small { display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sc-assistant-fact span { margin-top: 3px; color: color-mix(in srgb, currentColor 78%, transparent); font-size: 8px; font-weight: 700; letter-spacing: .3px; text-transform: uppercase; }
    .sc-assistant-fact strong { color: currentColor; font-size: 14px; font-variant-numeric: tabular-nums; }
    .sc-assistant-fact small { margin-top: 1px; color: color-mix(in srgb, currentColor 70%, transparent); font-size: 8.5px; }
    .sc-assistant-sev.critical, .sc-assistant-sev.error, .sc-assistant-sev.high, .sc-assistant-sev.medium, .sc-assistant-sev.warning, .sc-assistant-sev.low, .sc-assistant-sev.info, .sc-assistant-sev.information { color: currentColor; }
    .sc-assistant-panel { display: grid; gap: 0; padding: 13px; border: 1px solid color-mix(in srgb, var(--sc-primary) 16%, var(--sc-border)); border-radius: var(--sc-radius-lg); background: linear-gradient(180deg, color-mix(in srgb, var(--sc-primary) 4%, var(--sc-surface)), var(--sc-surface)); box-shadow: var(--sc-shadow-sm); overflow: hidden; }
    .sc-assistant-panel-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .sc-assistant-panel-head strong { color: var(--sc-text); font-size: 11px; }
    .sc-assistant-panel-body { display: grid; gap: 10px; margin-top: 11px; }
    .sc-assistant-recommendation { position: relative; display: grid; gap: 6px; margin: 0; padding: 10px 11px; border: 1px solid color-mix(in srgb, var(--sc-primary) 18%, var(--sc-border)); border-radius: var(--sc-radius-md); color: var(--sc-text); background: color-mix(in srgb, var(--sc-surface) 94%, transparent); font-size: 10.5px; line-height: 1.45; overflow-wrap: anywhere; box-shadow: 0 8px 18px color-mix(in srgb, var(--sc-text) 7%, transparent); }
    .sc-assistant-recommendation span { display: -webkit-box; -webkit-line-clamp: 4; -webkit-box-orient: vertical; overflow: hidden; }
    .sc-assistant-recommendation.sc-tone-alert { border-color: var(--sc-critical); }
    .sc-assistant-recommendation.sc-tone-attention { border-color: var(--sc-medium); }
    .sc-assistant-recommendation.sc-tone-good { border-color: var(--sc-low); }
    .sc-assistant-actions { display: flex; flex-wrap: wrap; gap: 6px; }
    .sc-assistant-action { flex: 1 1 auto; min-height: 26px; padding: 6px 10px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); color: var(--sc-text); background: var(--sc-surface); font: 600 10px var(--vscode-font-family); cursor: pointer; }
    .sc-assistant-action:hover { background: var(--sc-surface-soft); }
    .sc-assistant-action.primary { color: var(--vscode-button-foreground, #fff); background: var(--sc-primary); border-color: var(--sc-primary); }
    .sc-assistant-action.primary:hover { background: var(--sc-primary-hover, var(--sc-primary)); }
    .sc-assistant-hero-cta { justify-self: start; min-height: 24px; color: var(--vscode-button-foreground, #fff); background: var(--sc-primary); border-color: var(--sc-primary); }
    .sc-assistant-action:focus-visible, .sc-assistant-intent:focus-visible, .sc-assistant-send:focus-visible, .sc-assistant-collapse:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 1px; }
    .sc-assistant-tip { display: grid; gap: 5px; padding: 10px 11px; border: 1px solid color-mix(in srgb, var(--sc-primary) 14%, var(--sc-border)); border-radius: var(--sc-radius-md); background: color-mix(in srgb, var(--sc-primary) 7%, var(--sc-surface)); }
    .sc-assistant-tip strong { color: var(--sc-text); font-size: 10px; }
    .sc-assistant-tip span { color: var(--sc-muted); font-size: 10px; line-height: 1.45; }
      /* Entree vers la conversation complete. Meme jetons, aucune largeur ajoutee. */
  .sc-assistant-open { margin-top: 8px; }
  .sc-assistant-openchat { width: 100%; padding: 7px 10px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-sm); background: transparent; color: var(--sc-primary); font: 700 11px var(--vscode-font-family); cursor: pointer; }
  .sc-assistant-openchat:hover { border-color: var(--sc-primary); background: var(--sc-primary-soft); }
  .sc-assistant-ask { display: grid; grid-template-columns: minmax(0, 1fr) 28px; gap: 6px; align-items: center; padding-top: 2px; }
    .sc-assistant-intent { min-width: 0; min-height: 30px; padding: 6px 8px; border: 1px solid var(--sc-border); border-radius: var(--sc-radius-md); color: var(--sc-muted); background: var(--sc-surface); font: inherit; font-size: 10px; }
    .sc-assistant-send { width: 28px; height: 30px; border: 0; border-radius: var(--sc-radius-md); color: var(--vscode-button-foreground, #fff); background: var(--sc-primary); font-size: 11px; line-height: 1; cursor: pointer; }
    .sc-assistant-send:hover { background: var(--sc-primary-hover, var(--sc-primary)); }
    .sc-assistant-sr { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    /* Rail etroit : la mascotte passe au-dessus de la bulle plutot que de la
       comprimer a quelques caracteres par ligne. */
    @media (max-width: 1320px) {
      .sc-assistant-talk { grid-template-columns: 1fr; justify-items: start; gap: 7px; }
      .sc-assistant-bubble::before { display: none; }
      .sc-assistant-facts { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }
    @keyframes sc-companion-float { 0%,100%{transform:translateY(0) scale(1)} 50%{transform:translateY(-3px) scale(1.012)} }
    @keyframes sc-companion-analyze { 0%,100%{transform:translateY(0) scale(1)} 50%{transform:translateY(-4px) scale(1.018)} }
    @keyframes sc-companion-attend { 0%,100%{transform:translateY(0) scale(1)} 45%{transform:translateY(-2px) scale(1.014)} 60%{transform:translateY(0) scale(1.006)} }
    @keyframes sc-companion-glow { 0%,100%{opacity:.48;transform:scale(.9)} 50%{opacity:.82;transform:scale(1)} }
    @keyframes sc-companion-soft-pulse { 0%,100%{opacity:.52;transform:scale(.9)} 50%{opacity:.76;transform:scale(.98)} }
    @keyframes sc-companion-warning-glow { 0%,100%{opacity:.55;transform:scale(.9)} 50%{opacity:.86;transform:scale(1.02)} }
    @keyframes sc-companion-scan-ring { to{transform:rotate(360deg)} }
    @keyframes sc-companion-warning-ring { 0%,100%{transform:scale(.96);opacity:.3} 50%{transform:scale(1.04);opacity:.5} }
    @media (prefers-reduced-motion: reduce) { .sc-assistant .mascot, .sc-assistant-mascot, .sc-assistant-mascot::before, .sc-assistant-mascot::after { animation: none !important; transition: none !important; } .sc-assistant-mascot::after { opacity: 0; } }`;
}

/**
 * Le seul comportement de la carte, cote webview.
 *
 * Il relaie : rien d'autre. Un clic devient soit `{type:'command'}` avec une
 * commande du catalogue, soit un message dont le `type` est deja traite par la
 * page hote. « Pas maintenant » ne poste rien du tout — la suggestion disparait
 * visuellement, et aucun etat n'est ecrit nulle part.
 */
function assistantCardScript() {
  return `
    (function () {
      const stacks = Array.from(document.querySelectorAll('.sc-assistant-stack'));
      const roots = stacks.length ? stacks : Array.from(document.querySelectorAll('.sc-assistant, .sc-assistant-panel'));
      if (!roots.length) return;
      const api = typeof acquireVsCodeApi === 'function'
        ? (window.__scShellApi || (window.__scShellApi = acquireVsCodeApi()))
        : null;
      const ALLOWED_POST_TYPES = ${JSON.stringify(ASSISTANT_POST_TYPES)};
      const ALLOWED_POST_ACTIONS = ${JSON.stringify(ASSISTANT_POST_ACTIONS)};
      const run = function (button) {
        if (!button || !api) return;
        const raw = button.dataset.assistantPost;
        if (raw) {
          let payload = null;
          try { payload = JSON.parse(raw); } catch (error) { return; }
          if (!payload || ALLOWED_POST_TYPES.indexOf(payload.type) === -1) return;
          // Le type generique est partage par plusieurs pages : sa valeur est
          // verifiee elle aussi, sinon le controle ne dirait presque rien.
          if (payload.type === 'action' && ALLOWED_POST_ACTIONS.indexOf(payload.action) === -1) return;
          return api.postMessage(payload);
        }
        if (button.dataset.command) api.postMessage({ type: 'command', command: button.dataset.command });
      };
      roots.forEach(function (card) { card.addEventListener('click', function (event) {
        const collapse = event.target.closest('.sc-assistant-collapse');
        if (collapse) {
          const section = collapse.closest('.sc-assistant, .sc-assistant-panel') || card;
          const collapsed = section.dataset.collapsed === 'true';
          section.dataset.collapsed = collapsed ? 'false' : 'true';
          collapse.setAttribute('aria-expanded', collapsed ? 'true' : 'false');
          return;
        }
        // Suggestion ecartee : purement visuel, rien n'est envoye ni memorise.
        if (event.target.closest('.sc-assistant-dismiss')) {
          const panel = event.target.closest('.sc-assistant-panel') || card;
          panel.hidden = true;
          return;
        }
        if (event.target.closest('.sc-assistant-send')) {
          const panel = event.target.closest('.sc-assistant-panel, .sc-assistant-stack') || card;
          const select = panel.querySelector('.sc-assistant-intent');
          const chosen = select && select.value
            ? panel.querySelector('[data-assistant-intent="' + select.value + '"]')
            : null;
          return run(chosen);
        }
        const action = event.target.closest('.sc-assistant-action');
        if (action) { event.stopPropagation(); run(action); }
        // Repli generique : tout element porteur d'un message declare passe par
        // la meme validation. La delegation ne listait que quatre classes, si
        // bien qu'un bouton correctement declare mais nomme autrement etait
        // silencieusement ignore.
        const posted = event.target.closest('[data-assistant-post]');
        if (posted && !action) { event.stopPropagation(); run(posted); }
      }); });
    })();`;
}

module.exports = {
  buildAssistantCardModel, renderAssistantCard, renderAssistantHeroCard, renderAssistantPanelCard, assistantCardCss, assistantCardScript,
  assistantMessageFor, assistantMascotPresenceState, securityTipFor, resolveAction, actionIdsFor,
  COMMAND_ACTIONS, POST_ACTIONS, ASSISTANT_POST_TYPES, ASSISTANT_POST_ACTIONS, ASSISTANT_INTENTS, SURFACE_SELF_COMMAND,
  TIPS_BY_CWE, TIPS_BY_CATEGORY, FIX_MESSAGES, REACHABILITY_MESSAGES,
  SENSITIVE_FINDING_FIELDS, MAX_ACTIONS
};
