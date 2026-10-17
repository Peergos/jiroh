package org.peergos.iroh;

import java.net.URI;

/** A relay a test can point endpoints at and restart. */
interface TestRelay extends AutoCloseable {

    URI url();

    /** Stops the relay, dropping all client connections, and starts it again on the same port. */
    void restart(long downMillis) throws Exception;

    @Override
    void close();
}
