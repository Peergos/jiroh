package org.peergos.iroh;

import tech.kwik.core.log.BaseLogger;

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * kwik's log, into java.util.logging: errors that carry an exception (such as a connection aborted by an internal
 * error) at WARNING, other kwik errors at FINE. kwik's other categories stay off.
 */
final class KwikLog extends BaseLogger {

    private static final Logger LOG = Logger.getLogger("tech.kwik");

    @Override
    protected void log(String message) {
        LOG.fine(message);
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
