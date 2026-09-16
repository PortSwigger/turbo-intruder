package hp3.h3.qpack;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The QPACK dynamic table, RFC 9204 section 3.2.
 *
 * <p>A FIFO of field lines addressed by an absolute index that never changes for the lifetime of an
 * entry: the first entry inserted is index 0 and each insertion increments. An insertion evicts
 * from the oldest end until the new entry fits within the capacity, and an evicted index stays
 * spent — it is never reused, so a stale reference is an error rather than a different header.
 *
 * <p><b>One writer, many lock-free readers.</b> Insertions arrive on the peer's QPACK encoder
 * stream, which is a single stream read by a single thread, while every response in flight reads
 * the table to decode its headers. Rather than have thousands of readers contend on a monitor —
 * which costs far more here than the bytes it saves — each mutation publishes a fresh immutable
 * {@link Snapshot}, and readers take one and hold it for as long as they need a stable view.
 */
public final class QpackDynamicTable {

    /** RFC 9204 section 3.2.1: an entry costs its name, its value, and 32 octets of overhead. */
    private static final int ENTRY_OVERHEAD = 32;

    private volatile Snapshot snapshot;

    /**
     * @param maxCapacity the capacity advertised in {@code SETTINGS_QPACK_MAX_TABLE_CAPACITY}. The
     *     peer may choose to use less, but this is the value both ends must use to size the wrapped
     *     Required Insert Count, so it is fixed for the connection's lifetime.
     */
    public QpackDynamicTable(long maxCapacity) {
        this.maxCapacity = maxCapacity;
        this.snapshot = new Snapshot(new FieldLine[0], 0, 0, maxCapacity, maxCapacity);
    }

    private final long maxCapacity;

    /**
     * An immutable view of the table. Entries it holds stay readable even after the live table has
     * evicted them, so a decode in progress cannot be torn by a concurrent insertion.
     */
    public static final class Snapshot {

        private final FieldLine[] entries;
        private final long evictedCount;
        private final long size;
        private final long capacity;
        private final long maxCapacity;

        private Snapshot(FieldLine[] entries, long evictedCount, long size, long capacity,
                long maxCapacity) {
            this.entries = entries;
            this.evictedCount = evictedCount;
            this.size = size;
            this.capacity = capacity;
            this.maxCapacity = maxCapacity;
        }

        /** The entry at {@code absoluteIndex}, RFC 9204 section 3.2.4. */
        public FieldLine get(long absoluteIndex) throws QpackException {
            long insertCount = insertCount();
            if (absoluteIndex < evictedCount || absoluteIndex >= insertCount) {
                throw new QpackException("dynamic table index " + absoluteIndex
                        + " is not present: entries " + evictedCount + ".." + (insertCount - 1)
                        + " are live");
            }
            return entries[(int) (absoluteIndex - evictedCount)];
        }

        /** Total insertions over the table's lifetime, RFC 9204 section 3.2.4. */
        public long insertCount() {
            return evictedCount + entries.length;
        }

        public long capacity() {
            return capacity;
        }

        /** The capacity advertised in SETTINGS, which sizes the wrapped Required Insert Count. */
        public long maxCapacity() {
            return maxCapacity;
        }
    }

    /** The current view, stable for as long as the caller holds it. */
    public Snapshot snapshot() {
        return snapshot;
    }

    /**
     * Appends an entry, which becomes the highest absolute index, evicting older entries to make
     * room. An entry larger than the whole capacity empties the table without being inserted, which
     * RFC 9204 section 3.2.2 describes explicitly.
     */
    public void insert(FieldLine entry) {
        Snapshot current = snapshot;
        long entrySize = sizeOf(entry);
        List<FieldLine> entries = new ArrayList<>(Arrays.asList(current.entries));
        long size = current.size;
        long evictedCount = current.evictedCount;

        while (!entries.isEmpty() && size + entrySize > current.capacity) {
            size -= sizeOf(entries.remove(0));
            evictedCount++;
        }
        if (size + entrySize > current.capacity) {
            snapshot = new Snapshot(new FieldLine[0], evictedCount, 0, current.capacity,
                    maxCapacity);
            return;
        }
        entries.add(entry);
        snapshot = new Snapshot(entries.toArray(new FieldLine[0]), evictedCount,
                size + entrySize, current.capacity, maxCapacity);
    }

    /** The entry at {@code absoluteIndex} in the live table. */
    public FieldLine get(long absoluteIndex) throws QpackException {
        return snapshot.get(absoluteIndex);
    }

    public long insertCount() {
        return snapshot.insertCount();
    }

    public long capacity() {
        return snapshot.capacity();
    }

    /**
     * Applies a Set Dynamic Table Capacity instruction, RFC 9204 section 4.3.1, evicting whatever
     * no longer fits.
     */
    public void setCapacity(long newCapacity) {
        Snapshot current = snapshot;
        List<FieldLine> entries = new ArrayList<>(Arrays.asList(current.entries));
        long size = current.size;
        long evictedCount = current.evictedCount;

        while (!entries.isEmpty() && size > newCapacity) {
            size -= sizeOf(entries.remove(0));
            evictedCount++;
        }
        snapshot = new Snapshot(entries.toArray(new FieldLine[0]), evictedCount, size, newCapacity,
                maxCapacity);
    }

    /**
     * What {@code entry} costs the table, RFC 9204 section 3.2.1: 32 octets plus its name and its
     * value.
     *
     * <p>The one place that answer is worked out. Whether an entry fits decides both eviction here
     * and whether a QPACK gate can withhold that entry at all, and a caller that guesses low
     * inserts something the peer drops on arrival — leaving every field section referencing it
     * undecodable rather than merely blocked.
     *
     * <p>Counted in the octets the encoder writes. Literals go out as ISO-8859-1, one octet per
     * character, so the size is taken from those bytes rather than from Java's UTF-16 view.
     */
    public static long entrySize(FieldLine entry) {
        return ENTRY_OVERHEAD + octetLength(entry.name()) + octetLength(entry.value());
    }

    private static int octetLength(String value) {
        return value.getBytes(StandardCharsets.ISO_8859_1).length;
    }

    private static long sizeOf(FieldLine entry) {
        return entrySize(entry);
    }
}
