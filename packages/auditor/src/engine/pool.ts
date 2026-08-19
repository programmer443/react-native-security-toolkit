/**
 * Bounded concurrency.
 *
 * `Promise.all(allFiles.map(scan))` is explicitly forbidden (§46), and not as a
 * style preference: on a large repository it opens every file at once, which
 * exhausts file descriptors and holds every file's text in memory
 * simultaneously. This scheduler keeps a fixed number of tasks in flight and
 * hands results back as they complete.
 *
 * It also owns the stop condition. A scan has a wall-clock budget, and when that
 * budget is gone the honest thing to do is stop and *say so* — a partial result
 * labelled partial is useful, while a partial result labelled complete is a lie
 * about coverage.
 */

export interface BoundedMapOptions {
  /** Tasks in flight at once. Values below 1 are treated as 1. */
  readonly concurrency: number;
  /**
   * Checked before each task starts. Returning `true` stops the run.
   *
   * Tasks already in flight are allowed to finish: cancelling mid-task would
   * mean abandoning a file with no record of having started it.
   */
  readonly shouldStop?: () => boolean;
}

export interface BoundedMapResult<Output> {
  readonly results: readonly Output[];
  /** Number of items processed. Lower than the input length when the run stopped early. */
  readonly completed: number;
  /** True when {@link BoundedMapOptions.shouldStop} ended the run. */
  readonly stopped: boolean;
}

/**
 * Applies `worker` to every item with at most `concurrency` in flight.
 *
 * A worker that rejects fails the whole run: callers are expected to handle
 * per-item failure themselves, because "which file failed" is information only
 * they can put in a report.
 */
export async function mapBounded<Input, Output>(
  items: readonly Input[],
  worker: (item: Input, index: number) => Promise<Output>,
  options: BoundedMapOptions
): Promise<BoundedMapResult<Output>> {
  const concurrency = Math.max(1, Math.floor(options.concurrency));
  const results: Output[] = [];
  let cursor = 0;
  let completed = 0;
  let stopped = false;

  async function run(): Promise<void> {
    for (;;) {
      if (options.shouldStop?.() === true) {
        stopped = true;
        return;
      }
      const index = cursor;
      cursor += 1;
      if (index >= items.length) {
        return;
      }
      const item = items[index];
      if (item === undefined) {
        continue;
      }
      results[index] = await worker(item, index);
      completed += 1;
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => run());
  await Promise.all(workers);

  // Holes appear when the run stopped early; a caller should never see them.
  return {
    results: results.filter((value): value is Output => value !== undefined),
    completed,
    stopped,
  };
}
