package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

/**
 * Proxy class for Socket. Every method is transparently passed to the wrapped
 * socket instance, except for {@code getInputStream()}. That method is wrapped
 * in a {@code SNIInputStream} class, allowing for intercepting the raw ("wire")
 * traffic before it is passed to the user of the socket.
 *
 * @see SNIInputStream
 * @author Peter Wu
 */
public class WireSocket extends Socket {

    private final Socket sock;
    private SNIInputStream wrappedIS;

    public WireSocket(Socket sock) throws IOException {
        this.sock = sock;
        this.wrappedIS = new SNIInputStream(sock.getInputStream());
        sock.getInputStream();
    }

    @Override
    synchronized public SNIInputStream getInputStream() {
        return wrappedIS;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return sock.getOutputStream();
    }

    // the below methods are called from SSLSocketImpl
    @Override
    public synchronized void close() throws IOException {
        sock.close();
    }

    @Override
    public String toString() {
        return sock.toString();
    }

    // the below methods are called from BaseSSLSocketImpl
    @Override
    public SocketChannel getChannel() {
        return sock.getChannel();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return sock.getLocalSocketAddress();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return sock.getRemoteSocketAddress();
    }

    @Override
    public boolean isConnected() {
        return sock.isConnected();
    }

    @Override
    public boolean isBound() {
        return sock.isBound();
    }

    @Override
    public boolean isInputShutdown() {
        return sock.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return sock.isOutputShutdown();
    }

    @Override
    public InetAddress getInetAddress() {
        return sock.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return sock.getLocalAddress();
    }

    @Override
    public int getPort() {
        return sock.getPort();
    }

    @Override
    public int getLocalPort() {
        return sock.getLocalPort();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        sock.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return sock.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        sock.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return sock.getSoLinger();
    }

    @Override
    public synchronized int getSoTimeout() throws SocketException {
        return sock.getSoTimeout();
    }

    @Override
    public synchronized void setSendBufferSize(int size)
            throws SocketException {
        sock.setSendBufferSize(size);
    }

    @Override
    public synchronized int getSendBufferSize() throws SocketException {
        return sock.getSendBufferSize();
    }

    @Override
    public synchronized void setReceiveBufferSize(int size)
            throws SocketException {
        sock.setReceiveBufferSize(size);
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        sock.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return sock.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        sock.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return sock.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        sock.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return sock.getReuseAddress();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency,
            int bandwidth) {
        sock.setPerformancePreferences(connectionTime, latency, bandwidth);
    }
}
