const test = require('node:test');
const assert = require('node:assert/strict');
const { ThemeController } = require('../src/theme-controller');

test('theme controller defaults safely and broadcasts one global theme', () => {
  const persisted = [];
  const observed = [];
  const controller = new ThemeController('invalid', (theme) => persisted.push(theme));
  const subscription = controller.onDidChange((theme) => observed.push(theme));
  assert.equal(controller.getTheme(), 'light');
  assert.equal(controller.setTheme('dark'), true);
  assert.equal(controller.setTheme('dark'), false);
  assert.equal(controller.setTheme('unknown'), false);
  assert.deepEqual(observed, ['dark']);
  assert.deepEqual(persisted, ['dark']);
  subscription.dispose();
});
