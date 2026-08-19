import { mapBounded } from '../pool.js';

describe('bounded concurrency', () => {
  it('processes every item', async () => {
    const items = Array.from({ length: 50 }, (_, index) => index);

    const result = await mapBounded(items, async (item) => item * 2, { concurrency: 4 });

    expect(result.completed).toBe(50);
    expect(result.results).toHaveLength(50);
    expect(result.stopped).toBe(false);
  });

  it('never exceeds the configured concurrency', async () => {
    // The whole point of the scheduler: `Promise.all(files.map(scan))` opens
    // every file at once and holds every file's text in memory (§46).
    let inFlight = 0;
    let peak = 0;

    await mapBounded(
      Array.from({ length: 40 }, (_, index) => index),
      async () => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 1));
        inFlight -= 1;
      },
      { concurrency: 3 }
    );

    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1);
  });

  it('stops when told to, and says that it stopped', async () => {
    let processed = 0;

    const result = await mapBounded(
      Array.from({ length: 100 }, (_, index) => index),
      async (item) => {
        processed += 1;
        return item;
      },
      { concurrency: 1, shouldStop: () => processed >= 5 }
    );

    expect(result.stopped).toBe(true);
    expect(result.completed).toBeLessThan(100);
    // A partial result labelled partial is useful; one labelled complete is a
    // lie about coverage.
    expect(result.results).toHaveLength(result.completed);
  });

  it('treats a concurrency below one as one rather than doing nothing', async () => {
    const result = await mapBounded([1, 2, 3], async (item) => item, { concurrency: 0 });

    expect(result.completed).toBe(3);
  });

  it('handles an empty input list', async () => {
    const result = await mapBounded([], async (item) => item, { concurrency: 4 });

    expect(result).toEqual({ results: [], completed: 0, stopped: false });
  });
});
