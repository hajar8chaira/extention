const test = require('node:test');
const assert = require('node:assert/strict');
const { runWithConcurrency } = require('../src/scheduler');

test('respecte la limite de concurrence', async () => {
  let running = 0;
  let maximum = 0;
  const completed = [];
  await runWithConcurrency([1, 2, 3, 4, 5], 2, async (item) => {
    running += 1;
    maximum = Math.max(maximum, running);
    await new Promise((resolve) => setTimeout(resolve, 8));
    completed.push(item);
    running -= 1;
  });
  assert.equal(maximum, 2);
  assert.deepEqual(completed.sort(), [1, 2, 3, 4, 5]);
});

test('ne démarre plus de scanner après annulation', async () => {
  const controller = new AbortController();
  const started = [];
  const result = await runWithConcurrency([1, 2, 3, 4], 1, async (item) => {
    started.push(item);
    controller.abort();
  }, controller.signal);
  assert.deepEqual(started, [1]);
  assert.equal(result.skipped, 3);
});
