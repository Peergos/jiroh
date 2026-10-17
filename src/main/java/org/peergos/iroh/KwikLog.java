package org.peergos.iroh;

import tech.kwik.core.log.BaseLogger;

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * kwik's log, into java.util.logging: errors (internal errors, closes with an error, idle timeouts) at WARNING,
 * except the sender's busy wait notice, which is FINE. kwik's other categories stay off.
 */
final class KwikLog extends BaseLogger {

    private static final Logger LOG = Logger.getLogger("tech.kwik");

    private final boolean quietPeerCloses;

    KwikLog() {
        this(false);
    }

    /** @param quietPeerCloses  log a peer closing with an error code at FINE, for servers where that is routine */
    KwikLog(boolean quietPeerCloses) {
        this.quietPeerCloses = quietPeerCloses;
    }

    @Override
    protected void log(String message) {
        boolean routine = message.contains("busy wait") || (quietPeerCloses && message.contains("Peer closed the connection"));
        LOG.log(routine? Level.FINE: Level.WARNING, message);
    }

    @Override
    protected void log(String message, Throwable error) {
        LOG.log(Level.WARNING, message, error);
    }

    @Override
    protected void logWithHexDump(String message, byte[] data, int length) {
        LOG.finest(message);
    }

    @Override
    protected void logWithHexDump(String message, ByteBuffer data, int offset, int length) {
        LOG.finest(message);
    }
}
