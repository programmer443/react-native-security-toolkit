/**
 * Bridges async work to synchronous event handlers.
 *
 * Every asynchronous call in this app is triggered by a press or a switch, and a
 * handler cannot await. Rather than dropping the promise on the floor, this
 * attaches a rejection handler: the toolkit's checks resolve instead of
 * rejecting, so anything arriving here is unexpected and worth seeing in the log
 * rather than surfacing as an unhandled rejection warning.
 */
export function fireAndForget<A extends readonly unknown[]>(
  work: (...args: A) => Promise<unknown>
): (...args: A) => void {
  return (...args: A) => {
    work(...args).catch((error: unknown) => {
      console.log('[rnsec] unexpected rejection', String(error));
    });
  };
}
