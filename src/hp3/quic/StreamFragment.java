package hp3.quic;

public record StreamFragment(int streamId, long offset, byte[] data, boolean fin) {
    public StreamFragment {
        if (streamId < 0 || offset < 0 || data == null) {
            throw new IllegalArgumentException("invalid stream fragment");
        }
        data = data.clone();
    }

    @Override
    public byte[] data() {
        return data.clone();
    }
}
