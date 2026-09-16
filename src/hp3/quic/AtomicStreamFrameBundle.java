package hp3.quic;

import tech.kwik.core.frame.FrameProcessor;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class AtomicStreamFrameBundle extends QuicFrame {
    private final List<StreamFrame> frames;
    private final int frameLength;
    private final CompletableFuture<Long> sentAtNanos = new CompletableFuture<>();

    private AtomicStreamFrameBundle(List<StreamFrame> frames) {
        if (frames.isEmpty()) {
            throw new IllegalArgumentException("an atomic stream bundle must contain at least one frame");
        }
        this.frames = List.copyOf(frames);
        this.frameLength = frames.stream().mapToInt(StreamFrame::getFrameLength).sum();
    }

    public static AtomicStreamFrameBundle from(List<StreamFragment> fragments) {
        if (fragments == null) {
            throw new IllegalArgumentException("fragments must not be null");
        }
        return new AtomicStreamFrameBundle(fragments.stream()
                .map(fragment -> new StreamFrame(
                        fragment.streamId(),
                        fragment.offset(),
                        fragment.data(),
                        fragment.fin()))
                .toList());
    }

    /**
     * What one fragment will cost the release it goes into.
     *
     * <p>Measured by building the frame rather than by adding up varint widths, so a batch that
     * reserves budget per request reserves the same number the release later adds up. Two
     * statements of one size drift apart, and the one that drifts is the one no traffic goes
     * through.
     */
    public static int frameLengthOf(StreamFragment fragment) {
        return from(List.of(fragment)).getFrameLength();
    }

    public List<StreamFrame> streamFrames() {
        return frames;
    }

    /** Called by the transport logger after the datagram carrying this bundle has been sent. */
    void markSent(long timestampNanos) {
        sentAtNanos.complete(timestampNanos);
    }

    long awaitSent(long timeoutMillis) throws IOException {
        try {
            return sentAtNanos.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for the release datagram to be sent", exception);
        } catch (ExecutionException exception) {
            throw new IOException("The release datagram could not be sent", exception.getCause());
        } catch (TimeoutException exception) {
            throw new IOException("The release datagram was not sent within " + timeoutMillis + "ms", exception);
        }
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frames.forEach(frame -> frame.accept(frameProcessor, packet, metaData));
    }

    @Override
    public int getFrameLength() {
        return frameLength;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        if (buffer.remaining() < frameLength) {
            throw new IllegalArgumentException("insufficient buffer space for atomic stream bundle");
        }
        frames.forEach(frame -> frame.serialize(buffer));
    }
}
