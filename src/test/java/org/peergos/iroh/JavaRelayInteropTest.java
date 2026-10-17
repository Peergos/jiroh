package org.peergos.iroh;

/** {@link RelayInteropTest} through {@link RelayServer} instead of n0's iroh-relay. */
class JavaRelayInteropTest extends RelayInteropTest {

    @Override
    TestRelay newRelay() throws Exception {
        return new JavaRelay();
    }
}
