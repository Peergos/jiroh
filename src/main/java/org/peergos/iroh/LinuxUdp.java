package org.peergos.iroh;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteOrder;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

/**
 * A dual-stack UDP socket on Linux through the FFM API, for what DatagramChannel can't do: generic segmentation
 * offload (one sendmsg for many equally sized datagrams) and receive offload (one recvmsg for many). Struct offsets are
 * those of the 64-bit Linux ABI (x86_64 and aarch64).
 */
final class LinuxUdp implements Udp {

    private static final int AF_INET6 = 10, SOCK_DGRAM = 2, SOCK_CLOEXEC = 0x80000;
    private static final int SOL_SOCKET = 1, SO_SNDBUF = 7, SO_RCVBUF = 8;
    private static final int IPPROTO_IPV6 = 41, IPV6_V6ONLY = 26;
    private static final int SOL_UDP = 17, UDP_SEGMENT = 103, UDP_GRO = 104;
    private static final int SHUT_RDWR = 2, EINTR = 4, EIO = 5;
    private static final int SOCKADDR_IN6 = 28, MSGHDR = 56, IOVEC = 16, CONTROL = 64;
    private static final int MAX_SEGMENTS = 64;
    private static final int BUFFER = 65536;
    private static final int SOCKET_BUFFER = 8 * 1024 * 1024;

    private static final boolean AVAILABLE;
    private static final StructLayout CAPTURE;
    private static final VarHandle ERRNO;
    private static final MethodHandle SOCKET, SETSOCKOPT, BIND, GETSOCKNAME, SENDMSG, RECVMSG, SHUTDOWN, CLOSE, STRERROR;

    static {
        MethodHandle socket = null, setsockopt = null, bind = null, getsockname = null, sendmsg = null, recvmsg = null,
                shutdown = null, close = null, strerror = null;
        StructLayout capture = null;
        VarHandle errno = null;
        boolean available = false;
        String arch = System.getProperty("os.arch");
        if (System.getProperty("os.name").equals("Linux") && (arch.equals("amd64") || arch.equals("aarch64"))
                && !Boolean.getBoolean("jiroh.udp.nio")) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup libc = linker.defaultLookup();
                Linker.Option errnoOption = Linker.Option.captureCallState("errno");
                capture = Linker.Option.captureStateLayout();
                errno = capture.varHandle(MemoryLayout.PathElement.groupElement("errno"));
                socket = linker.downcallHandle(libc.find("socket").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT), errnoOption);
                setsockopt = linker.downcallHandle(libc.find("setsockopt").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT), errnoOption);
                bind = linker.downcallHandle(libc.find("bind").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT), errnoOption);
                getsockname = linker.downcallHandle(libc.find("getsockname").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, ADDRESS), errnoOption);
                sendmsg = linker.downcallHandle(libc.find("sendmsg").orElseThrow(),
                        FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_INT), errnoOption);
                recvmsg = linker.downcallHandle(libc.find("recvmsg").orElseThrow(),
                        FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_INT), errnoOption);
                shutdown = linker.downcallHandle(libc.find("shutdown").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT));
                close = linker.downcallHandle(libc.find("close").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT));
                strerror = linker.downcallHandle(libc.find("strerror").orElseThrow(),
                        FunctionDescriptor.of(ADDRESS, JAVA_INT));
                available = true;
            }
            catch (RuntimeException | LinkageError e) {
                available = false;
            }
        }
        AVAILABLE = available;
        CAPTURE = capture;
        ERRNO = errno;
        SOCKET = socket;
        SETSOCKOPT = setsockopt;
        BIND = bind;
        GETSOCKNAME = getsockname;
        SENDMSG = sendmsg;
        RECVMSG = recvmsg;
        SHUTDOWN = shutdown;
        CLOSE = close;
        STRERROR = strerror;
    }

    static boolean isAvailable() {
        return AVAILABLE;
    }

    private final int fd;
    private final InetSocketAddress localAddress;
    private final ThreadLocal<SendBuffers> sendBuffers = ThreadLocal.withInitial(SendBuffers::new);
    private volatile boolean segmentation = true;
    private volatile boolean closed;

    private LinuxUdp(int fd, InetSocketAddress localAddress) {
        this.fd = fd;
        this.localAddress = localAddress;
    }

    static LinuxUdp bind(InetSocketAddress bindAddress) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CAPTURE);
            int fd = (int) SOCKET.invokeExact(state, AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (fd < 0) {
                throw error("socket", state);
            }
            try {
                setInt(arena, state, fd, IPPROTO_IPV6, IPV6_V6ONLY, 0);
                setInt(arena, state, fd, SOL_UDP, UDP_GRO, 1);
                setInt(arena, state, fd, SOL_SOCKET, SO_RCVBUF, SOCKET_BUFFER);
                setInt(arena, state, fd, SOL_SOCKET, SO_SNDBUF, SOCKET_BUFFER);
                MemorySegment addr = arena.allocate(SOCKADDR_IN6);
                writeSockaddr(addr, bindAddress);
                if ((int) BIND.invokeExact(state, fd, addr, SOCKADDR_IN6) != 0) {
                    throw error("bind " + bindAddress, state);
                }
                MemorySegment length = arena.allocate(JAVA_INT);
                length.set(JAVA_INT, 0, SOCKADDR_IN6);
                if ((int) GETSOCKNAME.invokeExact(state, fd, addr, length) != 0) {
                    throw error("getsockname", state);
                }
                int port = readSockaddr(addr).getPort();
                return new LinuxUdp(fd, new InetSocketAddress(bindAddress.getAddress(), port));
            }
            catch (IOException | RuntimeException e) {
                int ignored = (int) CLOSE.invokeExact(fd);
                throw e;
            }
        }
        catch (IOException | RuntimeException | Error e) {
            throw e;
        }
        catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    private static void setInt(Arena arena, MemorySegment state, int fd, int level, int option, int value) throws Throwable {
        MemorySegment v = arena.allocate(JAVA_INT);
        v.set(JAVA_INT, 0, value);
        if ((int) SETSOCKOPT.invokeExact(state, fd, level, option, v, 4) != 0) {
            throw error("setsockopt " + level + "/" + option, state);
        }
    }

    @Override
    public InetSocketAddress localAddress() {
        return localAddress;
    }

    @Override
    public int maxSegments() {
        return segmentation ? MAX_SEGMENTS : 1;
    }

    @Override
    public void send(byte[] data, int offset, int length, InetSocketAddress destination) throws IOException {
        sendmsg(data, offset, length, 0, destination);
    }

    @Override
    public void sendSegmented(byte[] data, int offset, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        if (length <= segmentSize) {
            sendmsg(data, offset, length, 0, destination);
            return;
        }
        if (segmentation) {
            try {
                sendmsg(data, offset, length, segmentSize, destination);
                return;
            }
            catch (NativeError e) {
                if (e.errno != EIO) {
                    throw e;
                }
                // The kernel or device can't segment (e.g. no checksum offload): send one by one from now on.
                segmentation = false;
            }
        }
        Udp.super.sendSegmented(data, offset, length, segmentSize, destination);
    }

    /** Per thread native memory for sendmsg: msghdr, iovec, address, control and data. */
    private static final class SendBuffers {
        final MemorySegment msg, iov, name, control, data, state;

        SendBuffers() {
            Arena arena = Arena.ofAuto();
            msg = arena.allocate(MSGHDR, 8);
            iov = arena.allocate(IOVEC, 8);
            name = arena.allocate(SOCKADDR_IN6, 8);
            control = arena.allocate(CONTROL, 8);
            data = arena.allocate(BUFFER, 8);
            state = arena.allocate(CAPTURE);
        }
    }

    private void sendmsg(byte[] data, int offset, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        if (closed) {
            throw new SocketException("Socket is closed");
        }
        SendBuffers b = sendBuffers.get();
        MemorySegment.copy(data, offset, b.data, JAVA_BYTE, 0, length);
        writeSockaddr(b.name, destination);
        b.iov.set(ADDRESS, 0, b.data);
        b.iov.set(JAVA_LONG, 8, length);
        b.msg.fill((byte) 0);
        b.msg.set(ADDRESS, 0, b.name);
        b.msg.set(JAVA_INT, 8, SOCKADDR_IN6);
        b.msg.set(ADDRESS, 16, b.iov);
        b.msg.set(JAVA_LONG, 24, 1);
        if (segmentSize > 0) {
            // cmsghdr {size_t len; int level; int type;} followed by the u16 segment size
            b.control.fill((byte) 0);
            b.control.set(JAVA_LONG, 0, 16 + 2);
            b.control.set(JAVA_INT, 8, SOL_UDP);
            b.control.set(JAVA_INT, 12, UDP_SEGMENT);
            b.control.set(JAVA_SHORT, 16, (short) segmentSize);
            b.msg.set(ADDRESS, 32, b.control);
            b.msg.set(JAVA_LONG, 40, 24);
        }
        while (true) {
            long sent;
            try {
                sent = (long) SENDMSG.invokeExact(b.state, fd, b.msg, 0);
            }
            catch (Throwable t) {
                throw new IllegalStateException(t);
            }
            if (sent >= 0) {
                return;
            }
            int errno = (int) ERRNO.get(b.state, 0L);
            if (errno != EINTR) {
                throw closed ? new SocketException("Socket is closed") : new NativeError("sendmsg to " + destination, errno);
            }
        }
    }

    @Override
    public void receiveLoop(Sink sink) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment msg = arena.allocate(MSGHDR, 8);
            MemorySegment iov = arena.allocate(IOVEC, 8);
            MemorySegment name = arena.allocate(SOCKADDR_IN6, 8);
            MemorySegment control = arena.allocate(CONTROL, 8);
            MemorySegment buffer = arena.allocate(BUFFER, 8);
            MemorySegment state = arena.allocate(CAPTURE);
            byte[] data = new byte[BUFFER];
            iov.set(ADDRESS, 0, buffer);
            iov.set(JAVA_LONG, 8, BUFFER);
            while (!closed) {
                msg.fill((byte) 0);
                msg.set(ADDRESS, 0, name);
                msg.set(JAVA_INT, 8, SOCKADDR_IN6);
                msg.set(ADDRESS, 16, iov);
                msg.set(JAVA_LONG, 24, 1);
                msg.set(ADDRESS, 32, control);
                msg.set(JAVA_LONG, 40, CONTROL);
                long received;
                try {
                    received = (long) RECVMSG.invokeExact(state, fd, msg, 0);
                }
                catch (Throwable t) {
                    throw new IllegalStateException(t);
                }
                if (received < 0) {
                    int errno = (int) ERRNO.get(state, 0L);
                    if (closed) {
                        return;
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    throw new NativeError("recvmsg", errno);
                }
                if (closed) {
                    return;
                }
                if (msg.get(JAVA_INT, 8) == 0) {
                    // No source address: woken by shutdown.
                    continue;
                }
                InetSocketAddress source = readSockaddr(name);
                int segmentSize = groSegmentSize(control, msg.get(JAVA_LONG, 40));
                int length = (int) received;
                MemorySegment.copy(buffer, JAVA_BYTE, 0, data, 0, length);
                if (segmentSize <= 0 || segmentSize >= length) {
                    sink.datagram(source, data, 0, length);
                }
                else {
                    for (int offset = 0; offset < length; offset += segmentSize) {
                        sink.datagram(source, data, offset, Math.min(segmentSize, length - offset));
                    }
                }
            }
        }
    }

    private static int groSegmentSize(MemorySegment control, long controlLength) {
        long offset = 0;
        while (offset + 16 <= controlLength) {
            long length = control.get(JAVA_LONG, offset);
            if (length < 16) {
                return 0;
            }
            if (control.get(JAVA_INT, offset + 8) == SOL_UDP && control.get(JAVA_INT, offset + 12) == UDP_GRO) {
                return control.get(JAVA_INT, offset + 16);
            }
            offset += (length + 7) & ~7L;
        }
        return 0;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            // Wakes a thread blocked in recvmsg, even on an unconnected socket.
            int ignored = (int) SHUTDOWN.invokeExact(fd, SHUT_RDWR);
            ignored = (int) CLOSE.invokeExact(fd);
        }
        catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    private static void writeSockaddr(MemorySegment addr, InetSocketAddress address) {
        addr.fill((byte) 0);
        addr.set(JAVA_SHORT, 0, (short) AF_INET6);
        addr.set(JAVA_SHORT.withOrder(ByteOrder.BIG_ENDIAN), 2, (short) address.getPort());
        InetAddress ip = address.getAddress();
        if (ip.isAnyLocalAddress()) {
            return;
        }
        byte[] bytes = ip.getAddress();
        if (ip instanceof Inet4Address) {
            addr.set(JAVA_BYTE, 18, (byte) 0xff);
            addr.set(JAVA_BYTE, 19, (byte) 0xff);
            MemorySegment.copy(bytes, 0, addr, JAVA_BYTE, 20, 4);
        }
        else {
            MemorySegment.copy(bytes, 0, addr, JAVA_BYTE, 8, 16);
            addr.set(JAVA_INT, 24, ((Inet6Address) ip).getScopeId());
        }
    }

    private static InetSocketAddress readSockaddr(MemorySegment addr) {
        int port = Short.toUnsignedInt(addr.get(JAVA_SHORT.withOrder(ByteOrder.BIG_ENDIAN), 2));
        byte[] bytes = addr.asSlice(8, 16).toArray(JAVA_BYTE);
        try {
            boolean mapped = true;
            for (int i = 0; i < 10; i++) {
                mapped &= bytes[i] == 0;
            }
            mapped &= bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
            if (mapped) {
                return new InetSocketAddress(InetAddress.getByAddress(new byte[]{bytes[12], bytes[13], bytes[14], bytes[15]}), port);
            }
            int scope = addr.get(JAVA_INT, 24);
            InetAddress ip = scope != 0 ? Inet6Address.getByAddress(null, bytes, scope) : InetAddress.getByAddress(bytes);
            return new InetSocketAddress(ip, port);
        }
        catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static NativeError error(String call, MemorySegment state) {
        return new NativeError(call, (int) ERRNO.get(state, 0L));
    }

    static final class NativeError extends SocketException {
        final int errno;

        NativeError(String call, int errno) {
            super(call + ": " + strerror(errno) + " (errno " + errno + ")");
            this.errno = errno;
        }

        private static String strerror(int errno) {
            try {
                return ((MemorySegment) STRERROR.invokeExact(errno)).reinterpret(256).getString(0);
            }
            catch (Throwable t) {
                return "error";
            }
        }
    }
}
