const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Régression : le titre du panneau Live Security portait « Security Center â€”
// Live Security » — un tiret cadratin UTF-8 relu en cp1252 puis ré-enregistré,
// figé dans la source. Reproduit dans un Extension Host VS Code réel sur le
// VSIX installé : l'onglet s'affichait avec la séquence corrompue alors que
// les onze autres pages affichaient « — ».
//
// La séquence « â€ » ne peut pas apparaître légitimement dans du texte français
// ou anglais : sa seule origine est un aller-retour d'encodage raté.
const MOJIBAKE = /â€|Ã©|Ã¨|Ã |Ã§|Ãª/;

const SOURCE_ROOT = path.join(__dirname, '..', 'src');

function javascriptFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return javascriptFiles(target);
    return entry.isFile() && entry.name.endsWith('.js') ? [target] : [];
  });
}

test('aucune chaîne source ne porte de séquence d’encodage corrompue', () => {
  const corrupted = [];
  for (const file of javascriptFiles(SOURCE_ROOT)) {
    const text = fs.readFileSync(file, 'utf8');
    text.split(/\r?\n/).forEach((line, index) => {
      // semgrep.js documente volontairement le symptôme dans un commentaire :
      // c'est l'exemple, pas le défaut.
      if (line.trimStart().startsWith('*') || line.trimStart().startsWith('//')) return;
      if (MOJIBAKE.test(line)) corrupted.push(`${path.relative(SOURCE_ROOT, file)}:${index + 1} — ${line.trim().slice(0, 90)}`);
    });
  }
  assert.deepEqual(corrupted, [], `Encodage corrompu :\n${corrupted.join('\n')}`);
});

test('les titres d’onglets utilisent un vrai tiret cadratin', () => {
  const titles = [];
  for (const file of javascriptFiles(SOURCE_ROOT)) {
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/createWebviewPanel\([^,]+,\s*['"`]([^'"`]+)['"`]/g)) {
      titles.push(match[1]);
    }
  }
  assert.ok(titles.length >= 10, `titres trouvés : ${titles.length}`);
  // Chaque titre sépare le domaine de la page par « — ». Le tiret corrompu
  // « â€” » est exactement ce que l'onglet Live Security affichait.
  for (const title of titles) {
    assert.doesNotMatch(title, MOJIBAKE, `titre corrompu : ${title}`);
    assert.match(title, /—/, `titre sans tiret cadratin : ${title}`);
  }
});
