package hp3.quic;

import java.time.Duration;

/**
 * Connection parameters for the QUIC transport.
 *
 * <p>The handshake timeout default is 10 seconds, which looks generous until you measure it. On a
 * network where a middlebox drops the first QUIC Initial packets, the handshake completes only
 * after PTO backoff retransmits them: measured handshakes to quic.nginx.org, www.google.com and
 * interop.seemann.io all landed at 6-7 seconds, against 0.2 seconds for a host on a non-443 port.
 * A tighter default would report "HTTP/3 does not work" on any such network.
 *
 * @param handshakeTimeout  how long to wait for the QUIC handshake
 * @param idleTimeout       how long an idle connection is kept
 * @param verifyCertificates whether to validate the server certificate; off by default to match
 *                           Burp's own upstream behaviour, since a proxy that refuses bad
 *                           certificates cannot be used to test them
 */
public record QuicConfig(Duration handshakeTimeout, Duration idleTimeout, boolean verifyCertificates) {

    public static QuicConfig defaults() {
        return new QuicConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), false);
    }

    public QuicConfig withHandshakeTimeout(Duration timeout) {
        return new QuicConfig(timeout, idleTimeout, verifyCertificates);
    }

    public QuicConfig withVerifyCertificates(boolean verify) {
        return new QuicConfig(handshakeTimeout, idleTimeout, verify);
    }
}
