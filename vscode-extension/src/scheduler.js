async function runWithConcurrency(items, limit, worker, signal) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 1, items.length || 1));
  let nextIndex = 0;
  async function consume() {
    while (nextIndex < items.length && !signal?.aborted) {
      const index = nextIndex;
      nextIndex += 1;
      await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(safeLimit, items.length) }, () => consume()));
  return { started: nextIndex, skipped: items.length - nextIndex };
}

module.exports = { runWithConcurrency };
