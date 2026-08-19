/**
 * A byte-aware least-recently-used cache.
 *
 * Used for parse results, where the natural cache key is content and the natural
 * cost is memory. Bounding entries alone is not enough: a hundred entries can be
 * a megabyte or a gigabyte depending on what was parsed, and §46 asks for a
 * memory ceiling rather than a hope.
 */
export class LruCache<Value> {
  private readonly entries = new Map<string, { value: Value; bytes: number }>();
  private currentBytes = 0;

  constructor(
    private readonly maxEntries: number,
    private readonly maxBytes: number
  ) {}

  get(key: string): Value | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined) {
      return undefined;
    }
    // Reinsertion is what makes Map iteration order double as recency order.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, value: Value, bytes: number): void {
    const existing = this.entries.get(key);
    if (existing !== undefined) {
      this.currentBytes -= existing.bytes;
      this.entries.delete(key);
    }

    this.entries.set(key, { value, bytes });
    this.currentBytes += bytes;
    this.evict();
  }

  get size(): number {
    return this.entries.size;
  }

  get byteSize(): number {
    return this.currentBytes;
  }

  clear(): void {
    this.entries.clear();
    this.currentBytes = 0;
  }

  private evict(): void {
    while (
      this.entries.size > this.maxEntries ||
      (this.currentBytes > this.maxBytes && this.entries.size > 1)
    ) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) {
        return;
      }
      const entry = this.entries.get(oldest.value);
      this.entries.delete(oldest.value);
      this.currentBytes -= entry?.bytes ?? 0;
    }
  }
}
