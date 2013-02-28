package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLProtocolException;

/**
 * Wraps an InputStream that contains raw TLS bytes from a Socket (not the
 * InputStream of a SSLSocket!) and attempt to retrieve the server name from the
 * ClientHello message. Java up to at least 7 do not support SNI for a TLS
 * server role. This InputStream wrapper is a hack for be able to capture the
 * Server Name extension from the ClientHello message during the TLS handshake.
 *
 * Assuming an open, connected {@code Socket}, you have to: 1. Wrap that socket
 * instance and override its {@code getInputStream} method to use this class.
 * {@code WireSocket} is such a wrapper. 2. Acquire a {@code SNIInputStream}
 * instance using {@code getInputStream} and call the {@code readRecord} method
 * to start reading the ClientHello message. 3. Use the {@code getHostName}
 * method to determine the host name (if any). 4. Pass the wrapped socket to
 * {@code SSLSocketFactory.createSocket}. Be careful, if you pass the unwrapped
 * socket here, you will get a protocol error since the ClientHello message is
 * already read. The wrapped socket is transparent and will return all data that
 * was captured.
 *
 * @see WireSocket
 * @author Peter Wu
 */
public class SNIInputStream extends InputStream {

    private final static int RECORD_HEADER_LENGTH = 5;
    private final static int PROTOCOL_MESSAGES_MAX_LENGTH = 1 << 14;
    private final static int HANDSHAKE_DATA_OFFSET = RECORD_HEADER_LENGTH + 4;
    private static final Logger _logger =
            Logger.getLogger(SNIInputStream.class.getName());
    private final InputStream sslClientIn;
    private int readBytes;
    private int expectedLen;
    private byte[] helloBuf;
    private ClientHello clientHello;

    SNIInputStream(InputStream sslClientIn) {
        assert sslClientIn != null;
        this.sslClientIn = sslClientIn;
    }

    /**
     * @return DNS Host Name as provided by the Server Name extension in a
     * ClientHello message.
     */
    public String getHostName() {
        if (clientHello == null) {
            return null;
        }
        return clientHello.getHostName();
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        return read(b, 0, 1);
    }

    /**
     * Reads data from the wrapped socket. If this is the first read action, the
     * method will block until a full ClientHello message is read.
     */
    @Override
    synchronized public int read(byte[] b, int off, int len)
            throws IOException {
        if (b == null) {
            throw new NullPointerException();
        }
        if (off < 0 || len < 0 || off + len > b.length) {
            throw new IndexOutOfBoundsException();
        }

        if (readRecord() == -1) { // EOF during ClientHello read
            return -1;
        }

        int readLength = readFromBuffer(b, off, len);
        int read = sslClientIn.read(b, off + readLength, len - readLength);
        if (read == -1) {
            return -1;
        }
        readLength += read;

        return readLength;
    }

    private int readFromBuffer(byte[] b, int off, int len) {
        if (helloBuf != null) {
            int readCount = expectedLen - readBytes;
            if (readCount > len) {
                readCount = len;
            }
            System.arraycopy(helloBuf, readBytes, b, off, readCount);
            readBytes += readCount;
            if (expectedLen == readBytes) {
                helloBuf = null;
            }
            return readCount;
        }
        return 0;
    }

    private int byteI(int pos) {
        return helloBuf[pos] & 0xFF;
    }

    /**
     * Reads and parse the initial TLS record from wire, blocking if there is
     * not enough data available.
     *
     * @return -1 if an EOF occurred while reading the record, 0 otherwise.
     * @throws IOException when a error occurred while reading from the wrapped
     * input stream.
     */
    synchronized public int readRecord() throws IOException {
        if (expectedLen != 0) {
            // bytes have been parsed before
            return 0;
        }
        expectedLen = RECORD_HEADER_LENGTH;
        helloBuf = new byte[expectedLen];

        while (readBytes < expectedLen) {
            int read;
            read = sslClientIn.read(helloBuf, readBytes, expectedLen - readBytes);
            if (read < 0) {
                return -1;
            }
            readBytes += read;

            // first time we see header
            if (helloBuf.length == RECORD_HEADER_LENGTH
                    && readBytes == RECORD_HEADER_LENGTH) {
                int protocolMsgLen = (byteI(3) << 8) | byteI(4);
                if (protocolMsgLen > PROTOCOL_MESSAGES_MAX_LENGTH) {
                    throw new SSLProtocolException("Illegal protocol messages "
                            + "length " + protocolMsgLen);
                }
                expectedLen += protocolMsgLen;
                helloBuf = Arrays.copyOf(helloBuf, expectedLen);
            }
        }

        // reset so it can be used as position marker for readFromBuffer()
        readBytes = 0;

        parseRecord();
        return 0;
    }

    private void parseRecord() {
        if (helloBuf[0] != 0x16) {
            _logger.log(Level.WARNING, "Expected Handshake type 0x16, got 0x{0}",
                    Integer.toHexString(byteI(0)));
            return;
        }
        int pos = RECORD_HEADER_LENGTH;
        if (helloBuf[pos] != 1) {
            _logger.log(Level.WARNING,
                    "Expected ClientHello as first message type, got {0}",
                    helloBuf[pos]);
            return;
        }
        // FIXME: record payload can be spread over multiple messages
        int handshakeMsgLen = (byteI(6) << 16) | (byteI(7) << 8) | byteI(8);
        pos = HANDSHAKE_DATA_OFFSET;
        try {
            this.clientHello = new ClientHello(helloBuf, pos, handshakeMsgLen);
        } catch (RuntimeException ex) {
            _logger.log(Level.WARNING, "Failed to recognize ClientHelo", ex);
        }
    }

    private class ClientHello {

        private final int EXTENSION_TYPE_SERVER_NAME = 0; // server_name RFC 6066
        private final int NAME_TYPE_HOST_NAME = 0;
        private final byte[] data;
        private int pos;
        private final int maxLen;
        private String hostName;

        public ClientHello(byte[] data, int pos, int maxLen) {
            this.data = data;
            this.pos = pos;
            this.maxLen = pos + maxLen;
            eatBytes("ProtocolVersion", 2);
            eatBytes("Random", 32);
            readVariant("SessionID", 0, 32);
            readVariant("CipherSuite", 2, power2(16) - 2);
            readVariant("CompressionMethod", 1, power2(8) - 1);
            if (pos < maxLen) {
                /* RFC5246 7.4.1.2: The presence of extensions can be detected
                 * by determining whether there are bytes following the
                 * compression_methods at the end of the ClientHello. */
                readExtensions();
            }
        }

        private int power2(int exponent) {
            return 1 << exponent;
        }

        /**
         * Reads an integer of length size bytes, advancing the data pointer.
         */
        private int readInteger(String desc, int size) {
            int len = 0;
            eatBytes(desc, size);
            for (int i = 0; i < size; i++) {
                int chr = data[pos - i - 1] & 0xFF;
                len |= chr << (8 * i);
            }
            return len;
        }

        private int readVariant(String desc, int min, int max) {
            return readVariant(desc, min, max, true);
        }

        /**
         * Reads a sequence of variant bytes consisting of length and data.
         *
         * @param eatData true if the internal data pointer is not advanced by
         * the length of the payload.
         * @return The length of the variant payload.
         */
        private int readVariant(String desc, int min, int max, boolean eatData) {
            // determine number of bytes necessary to store the maximum length
            int size = 1;
            while (max >> (8 * size) != 0) {
                size++;
            }
            // read length of following data
            int len = readInteger(desc + " len", size);
            if (len < min || len > max) {
                throw new RuntimeException("Expected " + desc + " " + min + ".."
                        + max + ", got " + len);
            }
            eatBytes(desc, len);
            // unread data after verifying that the data is available.
            if (!eatData) {
                pos -= len;
            }
            return len;
        }

        private void eatBytes(String desc, int count) {
            if (pos + count > maxLen) {
                throw new RuntimeException("Not enough bytes for " + desc);
            }
            pos += count;
        }

        private void readExtensions() {
            int dataLength = readVariant("Extension", 0, power2(16) - 1, false);
            dataLength += pos;

            while (pos < dataLength) {
                int type = readInteger("ExtensionType", 2);
                int extLen = readVariant("extension_data", 0, power2(16) - 1, false);
                if (type == EXTENSION_TYPE_SERVER_NAME) {
                    processSNI();
                } else {
                    pos += extLen;
                }
            }
        }

        private void processSNI() {
            int snLength = readVariant("ServerNameList", 1, power2(16) - 1, false);
            snLength += pos;
            while (pos < snLength) {
                int nameType = readInteger("NameType", 1);
                if (nameType == NAME_TYPE_HOST_NAME) {
                    int hostNameLen = readVariant("HostName", 1, power2(16) - 1, false);
                    try {
                        /* RFC 6066, 3: "The ServerNameList MUST NOT contain more
                         * than one name of the same name_type." Let us ignore
                         * multiple records */
                        if (hostName == null) {
                            hostName = new String(data, pos, hostNameLen, "UTF-8");
                            _logger.fine("Found SNI hostname " + hostName);
                        }
                    } catch (UnsupportedEncodingException ex) {
                        throw new AssertionError("Impossible, UTF-8 is always supported");
                    }
                    eatBytes("HostName", hostNameLen);
                }
            }
        }

        private String getHostName() {
            return hostName;
        }
    }
}
