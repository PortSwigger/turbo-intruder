package hp3.h3;

import hp3.h3.qpack.FieldLine;
import hp3.h3.qpack.PrefixInteger;
import hp3.h3.qpack.QpackDecoder;
import hp3.h3.qpack.QpackDecoderStream;
import hp3.h3.qpack.QpackDynamicTable;
import hp3.h3.qpack.QpackEncoder;
import hp3.h3.qpack.QpackEncoderStream;
import hp3.h3.qpack.QpackException;
import hp3.quic.QuicStream;
import hp3.quic.QuicTransport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * An HTTP/3 client connection over a {@link QuicTransport}, RFC 9114.
 *
 * <p>On open it does what every HTTP/3 client must: a unidirectional control stream carrying
 * SETTINGS, plus QPACK encoder and decoder streams, RFC 9114 section 6.2.1.
 *
 * <p>The connection advertises a QPACK dynamic table, so a server need not repeat the headers it
 * sends on every response. Keeping that table in step costs one instruction per insertion in and
 * one acknowledgement per field section out. Those acknowledgements are enqueued by the response
 * threads and written by a single one, because at these request rates a monitor shared by every
 * response in flight costs far more than the bytes the table saves.
 *
 * <p>Knows nothing about Montoya. It speaks {@link Http3Request} and {@link Http3Response}, which
 * makes it testable against an in-memory transport and reusable outside Burp.
 */
public final class Http3ClientConnection implements AutoCloseable {

    private final QuicTransport transport;
    private QuicStream controlStream;
    private QuicStream qpackEncoderStream;
    private QuicStream qpackDecoderStream;
    private final AtomicBoolean peerControlSeen = new AtomicBoolean();
    private final AtomicBoolean peerQpackEncoderSeen = new AtomicBoolean();
    private final AtomicBoolean peerQpackDecoderSeen = new AtomicBoolean();
    private final AtomicBoolean peerFailure = new AtomicBoolean();
    private final AtomicBoolean closing = new AtomicBoolean();
    private volatile Http3Settings peerSettings = Http3Settings.empty();
    private final CountDownLatch peerSettingsSeen = new CountDownLatch(1);

    /** Our copy of the peer's dynamic table, written only by its QPACK encoder stream reader. */
    private final QpackDynamicTable peerTable;
    private final ConcurrentLinkedQueue<Long> sectionsToAcknowledge = new ConcurrentLinkedQueue<>();
    private final AtomicLong insertionsToAcknowledge = new AtomicLong();
    private final Semaphore decoderStreamWork = new Semaphore(0);

    /** The entries we insert into our own table, and how many the peer has taken in. */
    private final AtomicBoolean authorityInsertionStarted = new AtomicBoolean();
    /**
     * The authority entry every request currently references, with the absolute index it landed
     * at. The index is carried with the entry rather than recomputed from {@link #ourInsertCount}:
     * a gate stages many requests against one insertion, and re-deriving "the newest entry" per
     * request makes each of them depend on what has happened since.
     */
    private volatile QpackEncoder.DynamicEntry insertedAuthority;
    private final AtomicLong insertionsPeerHasTaken = new AtomicLong();
    /**
     * How many entries we have inserted, which is also the absolute index of the next one.
     *
     * <p>Absolute indices never restart, so this only grows. The peer evicts its oldest entries
     * once the table is full, which is harmless here because a field section only ever references
     * the newest.
     */
    private final AtomicLong ourInsertCount = new AtomicLong();
    /** Set by a hold, so the first request under it inserts an entry the peer does not have. */
    private final AtomicBoolean insertionOwedToHold = new AtomicBoolean();
    /** Set dynamic table capacity is a one-off; only the insertions repeat. */
    private final AtomicBoolean capacitySent = new AtomicBoolean();

    /** Encoder instructions withheld from the wire while the stream is held, and the flag. */
    private final AtomicBoolean holdingEncoderStream = new AtomicBoolean();
    private final ByteArrayOutputStream heldEncoderBytes = new ByteArrayOutputStream();
    /**
     * How many insertions the active hold has buffered. Exactly one is the only correct answer:
     * zero means nothing is blocked and the batch went out decodable, and more than one means the
     * batch is waiting on several entries rather than one shared barrier.
     */
    private long insertionsBufferedForHold;
    /**
     * The one entry every request under the active hold references. Held separately from
     * {@link #insertedAuthority}, which an ordinary request may have left behind from before the
     * hold: referencing that one would reference something the peer already has.
     */
    private volatile QpackEncoder.DynamicEntry heldGateEntry;
    /**
     * Set when a gate broke one of its own invariants. The connection carries encoder state the
     * peer no longer agrees with, so it must not be handed to another gate.
     */
    private final AtomicBoolean gateInvariantBroken = new AtomicBoolean();

    private Http3ClientConnection(QuicTransport transport, long maxTableCapacity) {
        this.transport = transport;
        this.peerTable = new QpackDynamicTable(maxTableCapacity);
    }

    /** Opens the control and QPACK streams and sends our SETTINGS. */
    public static Http3ClientConnection open(QuicTransport transport) throws IOException {
        return open(transport, Http3Settings.clientDefaults());
    }

    public static Http3ClientConnection open(QuicTransport transport, Http3Settings settings)
            throws IOException {
        var connection = new Http3ClientConnection(transport,
                settings.get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0));

        transport.onPeerStream(connection::dispatchPeerStream);

        connection.controlStream = transport.openUnidirectionalStream();
        OutputStream control = connection.controlStream.output();
        VarInt.write(control, Http3StreamType.CONTROL);
        Http3FrameWriter.write(control, Http3FrameType.SETTINGS, settings.encodePayload());
        control.flush();

        connection.qpackEncoderStream = openSilentStream(transport, Http3StreamType.QPACK_ENCODER);
        connection.qpackDecoderStream = openSilentStream(transport, Http3StreamType.QPACK_DECODER);
        connection.startDecoderStreamWriter();

        return connection;
    }

    private void dispatchPeerStream(QuicStream stream) {
        Thread.ofVirtual().name("h3-peer-stream-" + stream.id()).start(() -> {
            try {
                processPeerStream(stream);
            } catch (Throwable failure) {
                failConnection(failure);
            }
        });
    }

    private void processPeerStream(QuicStream stream) throws IOException {
        if (!stream.isUnidirectional()) {
            throw new Http3Exception(Http3Exception.H3_STREAM_CREATION_ERROR,
                    "server opened a bidirectional HTTP/3 stream");
        }

        InputStream input = stream.input();
        long streamType = VarInt.read(input);
        if (streamType < 0) {
            throw new Http3Exception(Http3Exception.H3_STREAM_CREATION_ERROR,
                    "peer unidirectional stream ended before its stream type");
        }

        if (streamType == Http3StreamType.CONTROL) {
            claimCriticalStream(peerControlSeen, "control");
            readPeerControlStream(input);
        } else if (streamType == Http3StreamType.QPACK_ENCODER) {
            claimCriticalStream(peerQpackEncoderSeen, "QPACK encoder");
            readPeerQpackEncoderStream(input);
        } else if (streamType == Http3StreamType.QPACK_DECODER) {
            claimCriticalStream(peerQpackDecoderSeen, "QPACK decoder");
            readPeerQpackDecoderStream(input);
        } else if (streamType == Http3StreamType.PUSH) {
            throw new Http3Exception(Http3Exception.H3_ID_ERROR,
                    "peer opened a push stream without an advertised maximum push ID");
        } else {
            input.transferTo(OutputStream.nullOutputStream());
        }
    }

    private static void claimCriticalStream(AtomicBoolean seen, String name)
            throws Http3Exception {
        if (!seen.compareAndSet(false, true)) {
            throw new Http3Exception(Http3Exception.H3_STREAM_CREATION_ERROR,
                    "peer opened a second " + name + " stream");
        }
    }

    private void readPeerControlStream(InputStream input) throws IOException {
        var reader = new Http3FrameReader(input);
        Http3Frame first = reader.readFrame();
        if (first == null || first.type() != Http3FrameType.SETTINGS) {
            throw new Http3Exception(Http3Exception.H3_MISSING_SETTINGS,
                    "peer control stream did not begin with SETTINGS");
        }
        peerSettings = Http3Settings.decodePayload(first.payload());
        peerSettingsSeen.countDown();

        Http3Frame frame;
        while ((frame = reader.readFrame()) != null) {
            if (Http3FrameType.isReservedHttp2Type(frame.type())) {
                throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                        "peer sent " + Http3FrameType.name(frame.type())
                                + " on its control stream");
            }
            if (frame.type() == Http3FrameType.SETTINGS
                    || frame.type() == Http3FrameType.DATA
                    || frame.type() == Http3FrameType.HEADERS
                    || frame.type() == Http3FrameType.PUSH_PROMISE
                    || frame.type() == Http3FrameType.CANCEL_PUSH
                    || frame.type() == Http3FrameType.MAX_PUSH_ID) {
                throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                        "peer sent " + Http3FrameType.name(frame.type())
                                + " on its control stream");
            }
        }
        throw new Http3Exception(Http3Exception.H3_CLOSED_CRITICAL_STREAM,
                "peer closed its control stream");
    }

    /**
     * Watches for the peer taking in the entries we insert. Until it has, referencing one would
     * block a request behind our own encoder stream, so requests keep spelling the value out.
     */
    private void readPeerQpackDecoderStream(InputStream input) throws IOException {
        while (true) {
            long increment;
            try {
                increment = QpackDecoderStream.readInsertCountIncrement(input);
            } catch (QpackException e) {
                throw new Http3Exception(Http3Exception.QPACK_DECODER_STREAM_ERROR, e.getMessage());
            }
            if (increment < 0) {
                break;
            }
            if (increment > 0) {
                insertionsPeerHasTaken.addAndGet(increment);
            }
        }
        throw new Http3Exception(Http3Exception.H3_CLOSED_CRITICAL_STREAM,
                "peer closed its QPACK decoder stream");
    }

    /** The request's {@code :authority}, or {@code null} if it has none. */
    private static FieldLine authorityOf(Http3Request request) {
        for (FieldLine field : request.fields()) {
            if (field.name().equals(":authority")) {
                return field;
            }
        }
        return null;
    }

    /**
     * The dynamic entry a request may reference instead of repeating, or {@code null} while there
     * is not one yet. The first request to arrive inserts its {@code :authority} — the one header a
     * fuzzing run repeats verbatim on every request — and the rest reference it once the peer says
     * it has taken the insertion in.
     */
    private QpackEncoder.DynamicEntry dynamicAuthorityEntry(Http3Request request)
            throws IOException {
        long peerCapacity = peerSettings.get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0);
        if (peerCapacity < 32) {
            return null;
        }
        FieldLine authority = authorityOf(request);
        if (authority == null) {
            return null;
        }
        boolean held = holdingEncoderStream.get();
        // A gate is only a gate while the peer is missing something. The first hold on a
        // connection is covered by the insertion below, but every later one has to insert again:
        // after a release the peer holds the previous entry, so referencing it decodes on arrival
        // and the batch is answered before the gate opens.
        if (held && insertionOwedToHold.compareAndSet(true, false)) {
            insertAuthority(authority, peerCapacity);
        } else if (insertedAuthority == null && authorityInsertionStarted.compareAndSet(false, true)) {
            insertAuthority(authority, peerCapacity);
        }
        // Re-read rather than assume: a request that lost the race to insert must not reference an
        // entry that has not been buffered yet.
        QpackEncoder.DynamicEntry inserted = insertedAuthority;
        if (inserted == null) {
            return null;
        }
        // A run that varies the authority is not what this helps, and mixing the two would mean
        // tracking more than one entry; the odd request out simply spells its value out.
        if (!inserted.field().equals(authority)) {
            return null;
        }
        // A held encoder stream has deliberately not delivered its insertion, so waiting for the
        // peer to acknowledge it would wait for ever.
        if (!held && insertionsPeerHasTaken.get() <= inserted.absoluteIndex()) {
            return null;
        }
        return inserted;
    }

    /**
     * Inserts {@code authority} into our dynamic table, sending the capacity once and the
     * insertion every time. Repeating the insertion is the point when a gate is held: it is a new
     * entry at a new absolute index, so the field section referencing it needs something the peer
     * has not been given yet.
     */
    private void insertAuthority(FieldLine authority, long peerCapacity) throws IOException {
        var instructions = new ByteArrayOutputStream();
        if (capacitySent.compareAndSet(false, true)) {
            instructions.writeBytes(QpackEncoderStream.encodeSetCapacity(peerCapacity));
        }
        // Static index 0 is ":authority" with an empty value.
        instructions.writeBytes(QpackEncoderStream.encodeInsertWithNameReference(0, authority.value()));
        byte[] bytes = instructions.toByteArray();

        // The index and the buffering are taken together, so a held gate's one insertion cannot be
        // handed an index that a concurrent insertion has already moved past.
        long absoluteIndex;
        boolean withheld;
        synchronized (heldEncoderBytes) {
            absoluteIndex = ourInsertCount.getAndIncrement();
            withheld = holdingEncoderStream.get();
            if (withheld) {
                heldEncoderBytes.writeBytes(bytes);
                insertionsBufferedForHold++;
            }
        }
        insertedAuthority = new QpackEncoder.DynamicEntry(authority, absoluteIndex);

        // Withholding is what makes a field section referencing the insertion unreadable to the
        // peer: it has the whole request but cannot decode its headers until the insertion
        // arrives. Anything not withheld goes out at once, outside the monitor a release wants.
        if (!withheld) {
            OutputStream out = qpackEncoderStream.output();
            out.write(bytes);
            out.flush();
        }
    }

    private static void drainCriticalStream(InputStream input, String name) throws IOException {
        input.transferTo(OutputStream.nullOutputStream());
        throw new Http3Exception(Http3Exception.H3_CLOSED_CRITICAL_STREAM,
                "peer closed its " + name + " stream");
    }

    /**
     * Applies the peer's encoder instructions to our copy of its table, telling it how far we have
     * got so it can start referencing what it has sent.
     */
    private void readPeerQpackEncoderStream(InputStream input) throws IOException {
        while (true) {
            long before = peerTable.insertCount();
            boolean more;
            try {
                more = QpackEncoderStream.readInstruction(input, peerTable);
            } catch (QpackException e) {
                throw new Http3Exception(Http3Exception.QPACK_ENCODER_STREAM_ERROR, e.getMessage());
            }
            if (!more) {
                break;
            }
            long inserted = peerTable.insertCount() - before;
            if (inserted > 0) {
                insertionsToAcknowledge.addAndGet(inserted);
                decoderStreamWork.release();
            }
        }
        throw new Http3Exception(Http3Exception.H3_CLOSED_CRITICAL_STREAM,
                "peer closed its QPACK encoder stream");
    }

    /**
     * Drains the pending decoder instructions onto the decoder stream, batching whatever has piled
     * up into one write. Producers only append to a queue and release a permit, so no response
     * thread ever waits on another.
     */
    private void startDecoderStreamWriter() {
        Thread.ofVirtual().name("h3-qpack-decoder-writer").start(() -> {
            try {
                while (!closing.get()) {
                    decoderStreamWork.acquire();
                    decoderStreamWork.drainPermits();
                    writePendingDecoderInstructions();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Throwable failure) {
                failConnection(failure);
            }
        });
    }

    private void writePendingDecoderInstructions() throws IOException {
        var batch = new ByteArrayOutputStream();
        long increment = insertionsToAcknowledge.getAndSet(0);
        if (increment > 0) {
            // Insert Count Increment, RFC 9204 section 4.4.3: "00" then the count.
            batch.writeBytes(PrefixInteger.encode(increment, 6, 0x00));
        }
        Long streamId;
        while ((streamId = sectionsToAcknowledge.poll()) != null) {
            // Section Acknowledgement, RFC 9204 section 4.4.1: "1" then the stream ID.
            batch.writeBytes(PrefixInteger.encode(streamId, 7, 0x80));
        }
        if (batch.size() == 0) {
            return;
        }
        OutputStream out = qpackDecoderStream.output();
        out.write(batch.toByteArray());
        out.flush();
    }

    private void failConnection(Throwable failure) {
        if (closing.get() || !peerFailure.compareAndSet(false, true)) {
            return;
        }
        long errorCode = failure instanceof Http3Exception
                ? ((Http3Exception) failure).errorCode()
                : Http3Exception.H3_GENERAL_PROTOCOL_ERROR;
        transport.close(errorCode, failure.getMessage() == null
                ? failure.getClass().getSimpleName()
                : failure.getMessage());
    }

    /**
     * Opens a unidirectional stream, declares its type and writes nothing more. Required by
     * RFC 9114 section 6.2.1 even though a zero-capacity dynamic table gives us nothing to say.
     */
    private static QuicStream openSilentStream(QuicTransport transport, long streamType)
            throws IOException {
        QuicStream stream = transport.openUnidirectionalStream();
        VarInt.write(stream.output(), streamType);
        stream.output().flush();
        return stream;
    }

    /** Sends {@code request} on a fresh bidirectional stream and reads the response. */
    public Http3Response send(Http3Request request) throws IOException {
        QuicStream stream = openRequestStream();
        writeRequest(stream, request);
        return readResponse(stream);
    }

    /**
     * Writes {@code request} to {@code stream} and finishes the sending half.
     *
     * <p>Composed into one buffer and written once. Writing the frames piecemeal costs a write per
     * varint, and a QUIC stream's output stream wakes its sender on each one, so a request that
     * fits in a single packet can end up spread across several STREAM frames.
     */
    public void writeRequest(QuicStream stream, Http3Request request) throws IOException {
        byte[] message = Http3FrameWriter.toBytes(Http3FrameType.HEADERS,
                QpackEncoder.encodeFieldSection(request.fields(), dynamicAuthorityEntry(request),
                        peerSettings.get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0)));
        if (request.hasBody()) {
            byte[] data = Http3FrameWriter.toBytes(Http3FrameType.DATA, request.body());
            byte[] combined = new byte[message.length + data.length];
            System.arraycopy(message, 0, combined, 0, message.length);
            System.arraycopy(data, 0, combined, message.length, data.length);
            message = combined;
        }
        OutputStream out = stream.output();
        out.write(message);
        out.flush();
        // Closing the sending half is HTTP/3's end of message; there is no END_STREAM flag.
        stream.finishSending();
    }

    /**
     * Encodes a request that must not be decodable until {@link #releaseEncoderStream()} runs, and
     * returns the bytes to put on its stream.
     *
     * <p>Separate from {@link #writeRequest} on purpose. That method may fall back to spelling a
     * value out whenever the dynamic table is unavailable, which is right for an ordinary request
     * and wrong for a gated one: a request that quietly stops referencing the withheld insertion is
     * answered on arrival, and the run reports a race it never ran. Everything that could make this
     * request decodable is checked here and fails the gate instead.
     *
     * <p>Nothing here needs a request stream, so a rejected request never leaves one half-open on
     * the connection.
     */
    public byte[] encodeBlockedRequest(Http3Request request) throws IOException {
        if (!holdingEncoderStream.get()) {
            throw brokenGate("a QPACK-blocked request was staged without holding the encoder "
                    + "stream, so nothing is being withheld for it to wait on");
        }
        long peerCapacity = peerSettings.get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0);
        FieldLine authority = authorityOf(request);
        if (authority == null) {
            throw brokenGate("a QPACK gate blocks every request on one withheld :authority "
                    + "insertion, and this request has no :authority to block on");
        }
        long entrySize = QpackDynamicTable.entrySize(authority);
        if (entrySize > peerCapacity) {
            throw brokenGate("this gate's dynamic table entry needs " + entrySize + " octets "
                    + "(RFC 9204 section 3.2.1: 32 + name + value), but the peer advertised "
                    + "QPACK_MAX_TABLE_CAPACITY=" + peerCapacity + ", so it would drop the "
                    + "insertion rather than store it and every request in the batch would fail "
                    + "to decode");
        }

        QpackEncoder.DynamicEntry entry = gateEntry(authority, peerCapacity);
        if (!entry.field().equals(authority)) {
            throw brokenGate("every request in a QPACK gate waits on the same insertion, so they "
                    + "must share one :authority: this gate withheld '" + entry.field().value()
                    + "' and this request asks for '" + authority.value() + "'");
        }

        byte[] fieldSection = QpackEncoder.encodeFieldSection(request.fields(), entry, peerCapacity);
        // Proof rather than inference. Buffered encoder bytes say some insertion is withheld; a
        // non-zero Required Insert Count says this request is the thing waiting on it. RFC 9204
        // section 4.5.1 encodes it as an 8-bit prefix integer, so zero is the leading octet.
        if (fieldSection[0] == 0) {
            throw brokenGate("this request's field section carries a Required Insert Count of "
                    + "zero, so the peer would decode it on arrival and the gate would hold "
                    + "nothing back");
        }

        byte[] message = Http3FrameWriter.toBytes(Http3FrameType.HEADERS, fieldSection);
        if (request.hasBody()) {
            byte[] data = Http3FrameWriter.toBytes(Http3FrameType.DATA, request.body());
            byte[] combined = new byte[message.length + data.length];
            System.arraycopy(message, 0, combined, 0, message.length);
            System.arraycopy(data, 0, combined, message.length, data.length);
            message = combined;
        }
        return message;
    }

    /**
     * The one entry the active hold withholds, inserting it for the first request to ask.
     *
     * <p>Every later request in the gate gets the same entry at the same absolute index, which is
     * what makes the batch one barrier rather than a queue of separate ones.
     */
    private QpackEncoder.DynamicEntry gateEntry(FieldLine authority, long peerCapacity)
            throws IOException {
        QpackEncoder.DynamicEntry entry = heldGateEntry;
        if (entry != null) {
            return entry;
        }
        synchronized (heldEncoderBytes) {
            entry = heldGateEntry;
            if (entry != null) {
                return entry;
            }
            if (insertionsBufferedForHold != 0) {
                throw brokenGate("this hold already withheld " + insertionsBufferedForHold
                        + " insertions before its gate staged anything, so the batch would wait "
                        + "on more than one entry");
            }
            // Claimed here so an ordinary writeRequest() on the same held connection cannot insert
            // a second entry under this hold.
            insertionOwedToHold.set(false);
            insertAuthority(authority, peerCapacity);
            heldGateEntry = insertedAuthority;
            return heldGateEntry;
        }
    }

    /** Writes a request that waits on the held gate, and finishes the sending half. */
    public void writeBlockedRequest(QuicStream stream, Http3Request request) throws IOException {
        writeBlockedRequest(stream, encodeBlockedRequest(request));
    }

    /**
     * Writes a request already encoded by {@link #encodeBlockedRequest}, and finishes the sending
     * half. Taking the bytes lets a caller do every check that can fail before it opens a stream.
     */
    public void writeBlockedRequest(QuicStream stream, byte[] encodedRequest) throws IOException {
        OutputStream out = stream.output();
        out.write(encodedRequest);
        out.flush();
        // Closing the sending half is HTTP/3's end of message; there is no END_STREAM flag.
        stream.finishSending();
    }

    /**
     * Opens a request stream without writing anything to it, for callers that intend to compose the
     * bytes themselves. A control seam: phase 2 uses this with
     * {@link Http3FrameWriter#writeWithDeclaredLength} and friends.
     */
    public QuicStream openRequestStream() throws IOException {
        return transport.openBidirectionalStream();
    }

    /** Reads a response from a stream the caller has already written and finished. */
    public Http3Response readResponse(QuicStream stream) throws IOException {
        return readResponse(stream.input(), stream.id());
    }

    /**
     * Reads a response from the bytes of an already-written stream. Taking the {@link InputStream}
     * rather than the stream lets a caller interpose on the bytes — timing the arrival of the first
     * one, for instance — without this class knowing about it.
     */
    public Http3Response readResponse(InputStream input) throws IOException {
        return readResponse(input, NO_STREAM_TO_ACKNOWLEDGE);
    }

    /** A stream ID no request stream can have, for reads that cannot acknowledge a field section. */
    private static final long NO_STREAM_TO_ACKNOWLEDGE = -1;

    /**
     * Reads a response, acknowledging on {@code streamId} any field section that referenced the
     * dynamic table. Acknowledging is what lets the peer reuse and evict its entries.
     */
    public Http3Response readResponse(InputStream input, long streamId) throws IOException {
        var reader = new Http3FrameReader(input);
        List<FieldLine> fields = null;
        List<FieldLine> trailers = List.of();
        var body = new ByteArrayOutputStream();

        Http3Frame frame;
        while ((frame = reader.readFrameIgnoringUnknown()) != null) {
            if (Http3FrameType.isReservedHttp2Type(frame.type())) {
                throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                        "peer sent " + Http3FrameType.name(frame.type())
                                + ", which HTTP/3 reserves and forbids");
            }
            if (frame.type() == Http3FrameType.HEADERS) {
                QpackDecoder.FieldSection section =
                        QpackDecoder.decodeSection(frame.payload(), peerTable);
                if (section.requiredInsertCount() > 0 && streamId != NO_STREAM_TO_ACKNOWLEDGE) {
                    sectionsToAcknowledge.add(streamId);
                    decoderStreamWork.release();
                }
                if (fields == null) {
                    fields = section.fields();
                } else {
                    // A second field section, after the body, is the trailer section.
                    trailers = section.fields();
                }
            } else if (frame.type() == Http3FrameType.DATA) {
                if (fields == null) {
                    throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                            "DATA arrived before any HEADERS frame");
                }
                body.writeBytes(frame.payload());
            }
            // Any other known frame type is legal here but of no interest to a client.
        }

        if (fields == null) {
            throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                    "response stream ended without a HEADERS frame");
        }
        return new Http3Response(fields, body.toByteArray(), trailers);
    }

    /**
     * How many entries the peer has inserted into the dynamic table we keep for it. Zero for the
     * whole of a connection means the peer is spelling every response header out, whatever capacity
     * we offered.
     */
    public long peerDynamicTableInsertCount() {
        return peerTable.insertCount();
    }

    /**
     * Waits up to {@code timeout} for the peer's SETTINGS and returns them, or returns whatever
     * has arrived by then — empty settings if nothing has.
     *
     * <p>A server sends SETTINGS on a control stream it opens itself, so they land shortly after
     * the handshake rather than as part of it. A caller that has to know what the peer allows
     * before it commits to a strategy — how much QPACK dynamic table there is, and how many
     * blocked streams it will tolerate — has to wait for them explicitly.
     */
    public Http3Settings awaitPeerSettings(long timeout, TimeUnit unit) {
        try {
            peerSettingsSeen.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return peerSettings;
    }

    /**
     * Stops writing QPACK encoder instructions to the wire, withholding them until
     * {@link #releaseEncoderStream()}.
     *
     * <p>Requests sent while held reference the withheld insertion, so the peer receives them
     * whole and complete but cannot decode a single one of their field sections. Releasing
     * unblocks all of them at once, which synchronises them without depending on when they were
     * sent or how many packets they took.
     *
     * <p>Idempotent for as long as the hold lasts. A gate holds once per request, because the hold
     * has to be in place before a byte of the first request is written and the caller staging the
     * second one cannot know it already is. Only the first of those holds owes an insertion: every
     * request in a gate must wait on the same entry, or the batch is several barriers rather than
     * one.
     */
    public void holdEncoderStream() {
        synchronized (heldEncoderBytes) {
            if (holdingEncoderStream.compareAndSet(false, true)) {
                insertionOwedToHold.set(true);
                insertionsBufferedForHold = 0;
                heldGateEntry = null;
            }
        }
    }

    /**
     * Delivers the instructions withheld while held, unblocking every request that waits on them.
     *
     * <p>Written in one call so the instructions leave in a single datagram: the release is what
     * every blocked request is synchronised on, so splitting it would stagger them by exactly the
     * jitter this is meant to remove.
     *
     * <p>A release that cannot prove it is unblocking exactly one shared insertion throws instead,
     * and leaves the hold in place. Returning quietly is how a batch that withheld nothing gets
     * reported as a clean release: every request was decodable on arrival, and the run reports a
     * race that was never run.
     */
    public void releaseEncoderStream() throws IOException {
        prepareEncoderStreamRelease().send();
    }

    /** A release with everything but the write already done. */
    @FunctionalInterface
    public interface PreparedRelease {
        void send() throws IOException;
    }

    /**
     * Ends the hold and hands back the write it leaves.
     *
     * <p>Whatever a release does before its write is time the gate spends holding a batch the
     * target already has, and the window a gate aims at is far finer than that work. So checking
     * the hold and taking its bytes both happen here, before the gate is opened.
     *
     * <p>The checks matter more than the copy. Thrown at the instant the gate opens they would
     * land with the batch already staged against the target; nothing about them depends on that
     * instant, so nothing about them waits for it.
     */
    public PreparedRelease prepareEncoderStreamRelease() throws IOException {
        byte[] instructions;
        synchronized (heldEncoderBytes) {
            if (!holdingEncoderStream.get()) {
                throw brokenGate("released a QPACK gate that is not holding its encoder stream");
            }
            if (insertionsBufferedForHold != 1) {
                throw brokenGate("a QPACK gate must withhold exactly one dynamic table insertion "
                        + "for its whole batch, but this one withheld " + insertionsBufferedForHold
                        + "; the batch was not released");
            }
            instructions = heldEncoderBytes.toByteArray();
            // Only now that the release is known to be valid does the hold end.
            heldEncoderBytes.reset();
            insertionsBufferedForHold = 0;
            heldGateEntry = null;
            holdingEncoderStream.set(false);
        }
        OutputStream out = qpackEncoderStream.output();
        return () -> {
            out.write(instructions);
            out.flush();
        };
    }

    /**
     * Records that a gate broke an invariant and builds the failure to throw. Marking the
     * connection stops it going back into the pool: whatever the peer's encoder state is now, it
     * is not what this connection thinks it is.
     */
    private Http3Exception brokenGate(String message) {
        gateInvariantBroken.set(true);
        return new Http3Exception(Http3Exception.H3_INTERNAL_ERROR, message);
    }

    public QuicStream controlStream() {
        return controlStream;
    }

    /**
     * The stream a QPACK gate withholds its insertion on. Exposed so a caller watching the wire can
     * tell the release apart from everything else in flight.
     */
    public long qpackEncoderStreamId() {
        return qpackEncoderStream.id();
    }

    public boolean isConnected() {
        return !gateInvariantBroken.get() && transport.isConnected();
    }

    @Override
    public void close() {
        closing.set(true);
        // Wake the decoder-stream writer so it sees the connection closing and stops.
        decoderStreamWork.release();
        transport.close();
    }
}
