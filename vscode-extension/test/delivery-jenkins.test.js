const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  DELIVERY_STATE, COMMIT_MATCH, normalizeJenkinsUrl, jenkinsJobPath, lastBuildUrl, jobUrl,
  buildStatusFrom, commitCorrelation, deliveryStatusFrom, fetchDeliveryStatus, scrubJenkinsError
} = require('../src/jenkins');
const { renderDeliveryPageHtml } = require('../src/delivery-page');
const { compareScans } = require('../src/scan-comparison');
const manifest = require('../package.json');

const SHA = 'abc123def456789012345678901234567890abcd';
const OTHER = 'def4567890123456789012345678901234567890';

// ------------------------------------------------- URL et chemin de job

test('une URL Jenkins portant des identifiants est refusée', () => {
  assert.throws(() => normalizeJenkinsUrl('http://user:token@ci.local'), /N’intégrez pas d’identifiants/);
  assert.throws(() => normalizeJenkinsUrl('ftp://ci.local'), /HTTP et HTTPS/);
  assert.throws(() => normalizeJenkinsUrl(''), /Renseignez l’URL/);
  assert.throws(() => normalizeJenkinsUrl('pas une url'), /invalide/);
  // La query et le fragment sont retirés : ils pourraient porter un jeton.
  assert.equal(normalizeJenkinsUrl('http://ci.local:8080/jenkins/?token=x#y'), 'http://ci.local:8080/jenkins');
  assert.equal(normalizeJenkinsUrl('http://ci.local:8080/'), 'http://ci.local:8080');
});

test('un chemin de job encode chaque segment et refuse la traversée', () => {
  assert.equal(jenkinsJobPath('security-center'), 'job/security-center');
  assert.equal(jenkinsJobPath('equipe/projet/main'), 'job/equipe/job/projet/job/main');
  assert.equal(jenkinsJobPath('mon job'), 'job/mon%20job');
  assert.throws(() => jenkinsJobPath('a/../etc'), /invalide/);
  assert.throws(() => jenkinsJobPath(''), /Renseignez le nom du job/);
});

test('aucun jeton ne peut se retrouver dans une URL construite', () => {
  const url = lastBuildUrl('http://ci.local:8080', 'equipe/projet');
  assert.match(url, /^http:\/\/ci\.local:8080\/job\/equipe\/job\/projet\/lastBuild\/api\/json\?tree=/);
  assert.ok(!/token|password|api[-_]?key/i.test(url));
  assert.equal(jobUrl('http://ci.local:8080/', 'projet'), 'http://ci.local:8080/job/projet/');
});

// ------------------------------------------------- normalisation du build

test('un build est normalisé sans rien inventer', () => {
  const build = buildStatusFrom({
    number: 184, result: 'FAILURE', building: false, timestamp: 1755400000000, duration: 91000,
    url: 'http://ci.local/job/x/184/', displayName: '#184',
    actions: [{}, { lastBuiltRevision: { SHA1: SHA, branch: [{ name: 'refs/remotes/origin/main', SHA1: SHA }] } }]
  });
  assert.equal(build.number, 184);
  assert.equal(build.state, DELIVERY_STATE.FAILED);
  assert.equal(build.result, 'FAILURE');
  assert.equal(build.commit, SHA);
  assert.equal(build.branch, 'main', 'le préfixe refs/remotes est retiré');
  assert.equal(build.durationMs, 91000);
  assert.ok(build.startedAt.startsWith('20'));
});

test('un build en cours n’a pas de résultat et le dit', () => {
  const build = buildStatusFrom({ number: 185, building: true, result: null });
  assert.equal(build.building, true);
  assert.equal(build.result, null, 'un build en cours n’a pas de verdict');
  assert.equal(build.state, DELIVERY_STATE.RUNNING);
});

test('les champs absents de l’API restent nuls', () => {
  const build = buildStatusFrom({ number: 3 });
  assert.equal(build.commit, null);
  assert.equal(build.branch, null);
  assert.equal(build.startedAt, null);
  assert.equal(build.durationMs, null);
  assert.equal(buildStatusFrom(null), null);
  assert.equal(buildStatusFrom('nope'), null);
});

test('le commit est repris du changeSet quand le plugin git ne le donne pas', () => {
  const build = buildStatusFrom({ number: 9, result: 'SUCCESS', changeSets: [{ items: [{ commitId: SHA }] }] });
  assert.equal(build.commit, SHA);
});

test('chaque résultat Jenkins a son état', () => {
  const state = (result) => buildStatusFrom({ number: 1, result }).state;
  assert.equal(state('SUCCESS'), DELIVERY_STATE.SUCCESS);
  assert.equal(state('FAILURE'), DELIVERY_STATE.FAILED);
  assert.equal(state('UNSTABLE'), DELIVERY_STATE.UNSTABLE);
  assert.equal(state('ABORTED'), DELIVERY_STATE.ABORTED);
  assert.equal(state(null), DELIVERY_STATE.NOT_STARTED);
});

// ---------------------------------------- corrélation commit / workspace

test('la correspondance de commit n’est jamais affirmée sans preuve', () => {
  assert.equal(commitCorrelation(SHA, SHA).match, COMMIT_MATCH.SAME);
  assert.equal(commitCorrelation('abc123d', SHA).match, COMMIT_MATCH.SAME, 'un SHA court correspond par préfixe');
  assert.equal(commitCorrelation(SHA, OTHER).match, COMMIT_MATCH.DIFFERENT);
  // Sans l'un des deux commits, aucune affirmation.
  assert.equal(commitCorrelation('', SHA).match, COMMIT_MATCH.UNKNOWN);
  assert.equal(commitCorrelation(SHA, '').match, COMMIT_MATCH.UNKNOWN);
  assert.equal(commitCorrelation('', '').match, COMMIT_MATCH.UNKNOWN);
  // Un préfixe trop court ne suffit pas à conclure à l'identité.
  assert.equal(commitCorrelation('abc', 'abc999999').match, COMMIT_MATCH.DIFFERENT);
});

// ------------------------------------------------- états de livraison

test('non configuré n’est ni une erreur ni un succès', () => {
  const status = deliveryStatusFrom({ configured: false, workspaceCommit: SHA });
  assert.equal(status.state, DELIVERY_STATE.NOT_CONFIGURED);
  assert.equal(status.build, null);
  assert.equal(status.policy, null);
  assert.equal(status.commit.match, COMMIT_MATCH.UNKNOWN);
});

test('un Jenkins injoignable est un état, pas une exception', async () => {
  const status = await fetchDeliveryStatus({
    baseUrl: 'http://ci.local', job: 'projet', workspaceCommit: SHA,
    request: async () => { throw new Error('Jenkins ne répond pas.'); }
  });
  assert.equal(status.state, DELIVERY_STATE.ERROR);
  assert.match(status.error, /ne répond pas/);
  assert.equal(status.build, null);
});

test('un job sans build est « aucun build », pas une erreur de configuration', async () => {
  const status = await fetchDeliveryStatus({
    baseUrl: 'http://ci.local', job: 'projet',
    request: async () => { throw new Error('Job Jenkins introuvable. Vérifiez le nom du job.'); }
  });
  assert.equal(status.state, DELIVERY_STATE.NOT_STARTED);
  assert.equal(status.error, '');
});

test('sans URL ni job, aucun appel réseau n’est tenté', async () => {
  let called = false;
  const status = await fetchDeliveryStatus({ baseUrl: '', job: '', request: async () => { called = true; return {}; } });
  assert.equal(called, false);
  assert.equal(status.state, DELIVERY_STATE.NOT_CONFIGURED);
});

test('un build lu produit un état complet avec corrélation', async () => {
  const status = await fetchDeliveryStatus({
    baseUrl: 'http://ci.local', job: 'projet', workspaceCommit: SHA,
    request: async () => ({ number: 184, result: 'SUCCESS', building: false, actions: [{ lastBuiltRevision: { SHA1: SHA } }] })
  });
  assert.equal(status.state, DELIVERY_STATE.SUCCESS);
  assert.equal(status.commit.match, COMMIT_MATCH.SAME);
  assert.equal(status.build.number, 184);
  assert.ok(status.fetchedAt);
});

// ------------------------------------------------------ non-fuite du jeton

test('aucun jeton ne franchit un message d’erreur', () => {
  assert.equal(scrubJenkinsError('connect http://user:tok3n@ci.local failed'), 'connect http://ci.local failed');
  assert.match(scrubJenkinsError('Authorization: Basic YWJjOmRlZg=='), /Basic \[REDACTED\]/);
  assert.match(scrubJenkinsError('Bearer eyJhbGciOi'), /Bearer \[REDACTED\]/);
});

test('la page de livraison ne contient jamais de jeton', () => {
  const status = deliveryStatusFrom({
    configured: true, job: 'projet', baseUrl: 'http://ci.local', workspaceCommit: SHA, fetchedAt: new Date().toISOString(),
    build: buildStatusFrom({ number: 184, result: 'SUCCESS', actions: [{ lastBuiltRevision: { SHA1: SHA } }] })
  });
  const html = renderDeliveryPageHtml(status, 'nonce', 'light');
  assert.ok(!/tok3n|Basic |Bearer |apiToken/i.test(html));
  // Et le jeton n'est même pas un champ du modèle.
  assert.ok(!('token' in status));
  assert.ok(!JSON.stringify(status).toLowerCase().includes('token'));
});

test('le jeton Jenkins n’est jamais un réglage', () => {
  const properties = Object.keys(manifest.contributes.configuration.properties);
  const jenkins = properties.filter((key) => key.includes('jenkins'));
  assert.deepEqual(jenkins.sort(), ['securityCenter.jenkins.job', 'securityCenter.jenkins.url', 'securityCenter.jenkins.user']);
  assert.ok(!jenkins.some((key) => /token|password|secret/i.test(key)), 'aucun secret dans les réglages');
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  // Le jeton passe par SecretStorage, jamais par la configuration.
  assert.match(source, /context\.secrets\.store\(JENKINS_TOKEN_SECRET_KEY/);
  assert.ok(!/update\('jenkins\.(token|apiToken)'/.test(source));
});

// --------------------------------------------------------- rendu de page

test('la page rend chaque état et garde une navigation parente', () => {
  for (const status of [
    deliveryStatusFrom({ configured: false }),
    deliveryStatusFrom({ configured: true, error: 'Jenkins ne répond pas.', job: 'p', baseUrl: 'http://ci.local' }),
    deliveryStatusFrom({ configured: true, build: null, job: 'p', baseUrl: 'http://ci.local' }),
    deliveryStatusFrom({ configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA, build: buildStatusFrom({ number: 1, building: true }) })
  ]) {
    const html = renderDeliveryPageHtml(status, 'n', 'light');
    assert.match(html, /Security Delivery/);
    assert.match(html, /data-command="securityCenter\.openDashboard"[^>]*>← Dashboard/, 'navigation parente obligatoire');
    assert.match(html, /Content-Security-Policy/);
    assert.ok(!html.includes('unsafe-eval'));
  }
});

test('un commit différent est signalé explicitement', () => {
  const status = deliveryStatusFrom({
    configured: true, job: 'p', baseUrl: 'http://ci.local', workspaceCommit: SHA,
    build: buildStatusFrom({ number: 1, result: 'SUCCESS', actions: [{ lastBuiltRevision: { SHA1: OTHER } }] })
  });
  const html = renderDeliveryPageHtml(status, 'n', 'light');
  assert.match(html, /commit différent de ce workspace/);
  assert.match(html, /ne porte pas sur le code actuellement ouvert/);
});

test('un verdict CI absent n’est pas remplacé par le verdict local', () => {
  const status = deliveryStatusFrom({ configured: true, job: 'p', baseUrl: 'http://ci.local', build: buildStatusFrom({ number: 1, result: 'SUCCESS' }) });
  const html = renderDeliveryPageHtml(status, 'n', 'light');
  assert.equal(status.policy, null);
  assert.match(html, /Non rapporté/);
  assert.match(html, /autre identité de scan/);
});

test('le contenu hostile est échappé avant rendu', () => {
  const status = deliveryStatusFrom({
    configured: true, job: '<img src=x onerror=alert(1)>', baseUrl: 'http://ci.local',
    build: buildStatusFrom({ number: 1, result: 'SUCCESS', actions: [{ lastBuiltRevision: { branch: [{ name: '<script>bad()</script>', SHA1: SHA }] } }] })
  });
  const html = renderDeliveryPageHtml(status, 'n', 'light');
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<script>bad()'));
});

// ---------------------------------------------------- Jenkinsfile modèle

test('le Jenkinsfile d’exemple bloque le déploiement et ne contient aucun secret', () => {
  const template = fs.readFileSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile'), 'utf8');
  // Le contrat de codes de sortie est documenté dans le fichier.
  assert.match(template, /0\s+accepté/);
  assert.match(template, /1\s+refusé/);
  assert.match(template, /2\s+échec d'exécution/);
  // Le gate doit lire le code de sortie, donc `returnStatus`.
  assert.match(template, /returnStatus:\s*true/);
  // Un BLOCK interrompt le pipeline avant Deploy, et Deploy a sa propre garde.
  assert.match(template, /Policy Gate BLOCK/);
  assert.match(template, /stage\('Deploy'\)[\s\S]*when\s*\{[\s\S]*SC_EXIT == '0'/);
  // Aucun identifiant en dur.
  assert.ok(!/[A-Za-z0-9+/]{32,}={0,2}/.test(template.replace(/[A-Za-z-]+\.jsonl?/g, '')), 'aucun secret encodé');
  assert.match(template, /credentials\('security-center-sonar-token'\)/);
});

// ---------------------------------------------------- régressions (Phase J)

const scan = (id, findings, scanners = [{ tool: 'Semgrep', status: 'completed' }]) => ({
  scan_id: id, result: { findings, scanners }
});
const finding = (overrides = {}) => ({
  tool: 'Semgrep', ruleId: 'sqli', title: 'Injection SQL', file: 'routes/login.ts',
  startLine: 41, rawSeverity: 'HIGH', ...overrides
});

test('une régression est un finding déjà traité qui revient', () => {
  const before = scan(1, [finding({ triageStatus: 'validated' })]);
  const after = scan(2, [finding({ triageStatus: 'new' })]);
  const diff = compareScans(before, after);
  assert.equal(diff.regressed.length, 1);
  assert.equal(diff.persistent.length, 1, 'une régression est aussi persistante par identité');
  assert.equal(diff.added.length, 0, 'ce n’est pas un nouveau finding');
  assert.equal(diff.perTool[0].regressed, 1);
});

test('les quatre verdicts de clôture comptent comme « traité »', () => {
  for (const status of ['validated', 'fixed', 'false_positive', 'accepted']) {
    const diff = compareScans(scan(1, [finding({ triageStatus: status })]), scan(2, [finding({ triageStatus: 'new' })]));
    assert.equal(diff.regressed.length, 1, `${status} doit pouvoir régresser`);
  }
});

test('un finding jamais vu est NOUVEAU, pas une régression', () => {
  const diff = compareScans(scan(1, []), scan(2, [finding({ triageStatus: 'new' })]));
  assert.equal(diff.added.length, 1);
  assert.equal(diff.regressed.length, 0, 'ne jamais avoir été vu n’est pas avoir été résolu');
});

test('un verdict qui se maintient n’est pas une régression', () => {
  const diff = compareScans(scan(1, [finding({ triageStatus: 'accepted' })]), scan(2, [finding({ triageStatus: 'accepted' })]));
  assert.equal(diff.regressed.length, 0);
  assert.equal(diff.persistent.length, 1);
});

test('un finding ouvert qui reste ouvert n’est pas une régression', () => {
  const diff = compareScans(scan(1, [finding({ triageStatus: 'new' })]), scan(2, [finding({ triageStatus: 'confirmed' })]));
  assert.equal(diff.regressed.length, 0);
});

test('la régression se fonde sur l’identité, pas sur le titre', () => {
  const before = scan(1, [finding({ triageStatus: 'validated' })]);
  // Même identité, titre reformulé par une mise à jour de règle.
  const after = scan(2, [finding({ triageStatus: 'new', title: 'SQL injection (CWE-89)' })]);
  assert.equal(compareScans(before, after).regressed.length, 1);
  // Titre identique mais autre emplacement : ce n'est pas la même chose.
  const elsewhere = scan(2, [finding({ triageStatus: 'new', file: 'routes/other.ts' })]);
  assert.equal(compareScans(before, elsewhere).regressed.length, 0);
});

test('un scanner non comparable est exclu et signalé', () => {
  const before = scan(1, [finding({ triageStatus: 'validated' })], [{ tool: 'Semgrep', status: 'completed' }]);
  const after = scan(2, [finding({ triageStatus: 'new' })], [{ tool: 'Semgrep', status: 'failed' }]);
  const diff = compareScans(before, after);
  // Semgrep a échoué : on ne conclut pas à une régression sur un scan incomplet.
  assert.ok(diff.excludedTools.includes('Semgrep'));
  assert.equal(diff.regressed.length, 0);
});

// -------------------------------------- audit d'accès (Phase A / Phase L)

test('chaque commande déclarée a un handler, y compris celles enregistrées en boucle', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.js'), 'utf8');
  const registered = new Set([...source.matchAll(/registerCommand\(\s*'([\w.]+)'/g)].map((m) => m[1]));
  // Les commandes de page sont enregistrées dynamiquement par une boucle ; un
  // audit qui l'ignore produit de faux positifs.
  const loop = source.match(/for \(const page of \[([^\]]+)\]\)[\s\S]{0,320}?registerCommand\(command/);
  if (loop) {
    for (const raw of loop[1].split(',')) {
      const page = raw.trim().replace(/['"]/g, '');
      if (page) registered.add(`securityCenter.open${page[0].toUpperCase()}${page.slice(1)}Page`);
    }
  }
  const missing = manifest.contributes.commands.map((c) => c.command).filter((command) => !registered.has(command));
  assert.deepEqual(missing, [], `commandes déclarées sans handler : ${missing.join(', ')}`);
});

test('les nouvelles commandes de livraison sont déclarées et activables', () => {
  const commands = manifest.contributes.commands.map((c) => c.command);
  for (const command of ['securityCenter.openSecurityDelivery', 'securityCenter.configureJenkins', 'securityCenter.openJenkinsfileTemplate']) {
    assert.ok(commands.includes(command), `${command} absente du manifeste`);
  }
  for (const event of ['onCommand:securityCenter.openSecurityDelivery', 'onCommand:securityCenter.configureJenkins']) {
    assert.ok(manifest.activationEvents.includes(event), `${event} manquant`);
  }
});

test('deux findings sans identifiant ne collident plus', () => {
  const { findingIdentity } = require('../src/scan-comparison');
  const a = { tool: 'Semgrep', ruleId: 'sqli', file: 'a.ts', startLine: 4 };
  const b = { tool: 'Semgrep', ruleId: 'sqli', file: 'b.ts', startLine: 9 };
  // Avant, les deux renvoyaient `undefined` et se confondaient.
  assert.notEqual(findingIdentity(a), findingIdentity(b));
  assert.ok(findingIdentity(a));
  // L'empreinte du scanner et l'identifiant normalisé restent prioritaires.
  assert.equal(findingIdentity({ fingerprint: 'fp-1', id: 'x' }), 'fp-1');
  assert.equal(findingIdentity({ id: 'zap:1' }), 'zap:1');
});

// ------------------------------------------------ packaging (Phase N)

test('le paquet exclut les artefacts de développement et les secrets', () => {
  const ignore = fs.readFileSync(path.join(__dirname, '..', '.vscodeignore'), 'utf8')
    .split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  for (const pattern of ['.codex-backups/**', '.codegraph/**', '.env', '*.vsix', '*.key', '*.pem', 'test/**']) {
    assert.ok(ignore.includes(pattern), `${pattern} doit être exclu du paquet`);
  }
});

test('le modèle Jenkinsfile est bien livré, lui', () => {
  const ignore = fs.readFileSync(path.join(__dirname, '..', '.vscodeignore'), 'utf8');
  assert.ok(!/^templates/m.test(ignore), 'le modèle Jenkinsfile doit rester dans le paquet');
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'templates', 'Jenkinsfile')));
});
