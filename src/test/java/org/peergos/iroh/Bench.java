package org.peergos.iroh;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

/**
 * Throughput benchmark, wire compatible with interop-probe's bench binary. Usage:
 *   Bench server [port]
 *   Bench client <host:port> <endpoint_id_hex> <up|down> <bytes> [streams]
 */
public final class Bench implements ProtocolHandler {

    static final String ALPN = "iroh-bench/0";
    private static final int CHUNK = 64 * 1024;

    // Progress watchdog: prints the connection's state when a transfer makes no progress for a while.
    private static final java.util.concurrent.atomic.AtomicLong progress = new java.util.concurrent.atomic.AtomicLong();
    private static volatile tech.kwik.core.impl.QuicConnectionImpl watched;

    private static void startWatchdog() {
        Thread.ofPlatform().daemon().start(() -> {
            long last = -1;
            int still = 0;
            while (true) {
                try {
                    Thread.sleep(1000);
                }
                catch (InterruptedException e) {
                    return;
                }
                long now = progress.get();
                tech.kwik.core.impl.QuicConnectionImpl connection = watched;
                if (now == last && connection != null) {
                    if (++still == 4) {
                        System.err.println("STALL at " + now + ": " + connection.debugState());
                    }
                }
                else {
                    still = 0;
                }
                last = now;
            }
        });
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        if (args[0].equals("server")) {
            int port = args.length > 1 ? Integer.parseInt(args[1]) : 0;
            Endpoint endpoint = endpoint(port).protocol(ALPN, new Bench()).build();
            System.out.println("endpoint id: " + endpoint.id().toHex());
            System.out.println("bound: " + endpoint.localAddress());
            Thread.currentThread().join();
        }
        else {
            client(args);
        }
    }

    private static Endpoint.Builder endpoint(int port) {
        return Endpoint.builder(SecretKey.generate())
                .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port))
                .streamReceiveWindow(Long.getLong("bench.window", Endpoint.DEFAULT_STREAM_RECEIVE_WINDOW));
    }

    @Override
    public void acceptStream(EndpointId remote, InetSocketAddress remoteAddress, QuicStream stream) {
        if (stream instanceof tech.kwik.core.stream.QuicStreamImpl impl) {
            watched = impl.getConnectionImpl();
        }
        (Boolean.getBoolean("bench.platform") ? Thread.ofPlatform() : Thread.ofVirtual()).start(() -> {
            try (OutputStream out = stream.getOutputStream()) {
                DataInputStream in = new DataInputStream(stream.getInputStream());
                int mode = in.readUnsignedByte();
                long size = in.readLong();
                if (mode == 'u') {
                    new DataOutputStream(out).writeLong(drain(in));
                    if (Boolean.getBoolean("bench.stats") && watched != null) {
                        System.out.println("server " + watched.getStats());
                    }
                }
                else {
                    writeBytes(out, size);
                }
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    private static void client(String[] args) throws Exception {
        String[] hostPort = args[1].split(":");
        InetSocketAddress addr = new InetSocketAddress(hostPort[0], Integer.parseInt(hostPort[1]));
        EndpointId id = EndpointId.fromHex(args[2]);
        boolean upload = args[3].equals("up");
        long size = Long.parseLong(args[4]);
        int streams = args.length > 5 ? Integer.parseInt(args[5]) : 1;
        int runs = Integer.getInteger("bench.runs", 3);
        try (Endpoint endpoint = endpoint(0).build();
             ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            QuicClientConnection connection = endpoint.connect(id, addr, ALPN);
            for (int run = 0; run < runs; run++) {
                long perStream = size / streams;
                long start = System.nanoTime();
                List<Future<Long>> tasks = new ArrayList<>();
                for (int i = 0; i < streams; i++) {
                    tasks.add(pool.submit(() -> transfer(connection, upload, perStream)));
                }
                long total = 0;
                for (Future<Long> t : tasks) {
                    total += t.get();
                }
                double secs = (System.nanoTime() - start) / 1e9;
                System.out.printf("%s %d bytes in %.3fs = %.1f MiB/s%n", args[3], total, secs, total / secs / (1 << 20));
            }
            if (Boolean.getBoolean("bench.stats")) {
                System.out.println(connection.getStats());
            }
            connection.close();
        }
    }

    private static long transfer(QuicClientConnection connection, boolean upload, long size) throws IOException {
        QuicStream stream = connection.createStream(true);
        watched = (tech.kwik.core.impl.QuicConnectionImpl) connection;
        DataOutputStream out = new DataOutputStream(stream.getOutputStream());
        out.writeByte(upload ? 'u' : 'd');
        out.writeLong(size);
        if (upload) {
            writeBytes(out, size);
            out.close();
            long count = new DataInputStream(stream.getInputStream()).readLong();
            if (count != size) {
                throw new IOException("short upload " + count);
            }
            return count;
        }
        out.close();
        long total = drain(stream.getInputStream());
        if (total != size) {
            throw new IOException("short download " + total);
        }
        return total;
    }

    private static long drain(InputStream in) throws IOException {
        byte[] buf = new byte[CHUNK];
        long total = 0;
        for (int n; (n = in.read(buf)) > 0; ) {
            total += n;
            progress.addAndGet(n);
        }
        return total;
    }

    private static void writeBytes(OutputStream out, long size) throws IOException {
        byte[] buf = new byte[CHUNK];
        java.util.Arrays.fill(buf, (byte) 0xab);
        for (long left = size; left > 0; ) {
            int n = (int) Math.min(left, CHUNK);
            out.write(buf, 0, n);
            left -= n;
            progress.addAndGet(n);
        }
    }
}
