/*
 * Message.java
 *
 * Created on May 12, 2003, 11:10 PM
 */

package org.owasp.webscarab.model;

import java.io.InputStream;
import java.io.OutputStream;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.StringBuffer;
import java.lang.NumberFormatException;

/** Message is a class that is used to represent the bulk of an HTTP message, namely
 * the headers, and (possibly null) body. Messages should not be instantiated
 * directly, but should rather be created by a derived class, namely Request or
 * Response.
 * @author rdawes
 */
public class Message extends Header {
    
    // we use a ByteArrayOutputStream to support bit-by-bit output in write()
    ByteArrayOutputStream content = null;
    
    InputStream contentStream = null;
    
    /** Message is a class that is used to represent the bulk of an HTTP message, namely
     * the headers, and (possibly null) body. Messages should not be instantiated
     * directly, but should rather be created by a derived class, namely Request or
     * Response.
     */
    protected Message() {
    }
    
    /** Instructs the class to read the headers from the InputStream, and assign the
     * InputStream as the contentStream, from which the body of the message can be
     * read.
     * @throws IOException Propagates any IOExceptions thrown by the InputStream read methods
     */    
    protected void read(InputStream is) throws IOException {
        super.read(is);
        contentStream = is;
    }
    
    /** Writes the Message (headers and content) to the supplied OutputStream */    
    protected void write(OutputStream os) throws IOException {
        write(os, "\r\n");
    }
    
    /** Writes the Message (headers and content) to the supplied OutputStream, using the
     * user supplied string to separate lines.
     */    
    protected void write(OutputStream os, String crlf) throws IOException {
        super.write(os, crlf);
        os.write(crlf.getBytes());
        if (content != null) {
            os.write(content.toByteArray());
        } else if (contentStream != null) {
            content = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int got = contentStream.read(buf);
            while (got > 0) {
                os.write(buf,0,got);
                content.write(buf,0,got);
                got = contentStream.read(buf);
            }
            contentStream = null;
        }
    }
    
    /** getContent returns the message body that accompanied the request. If
     * the class was read from an InputStream, this method will return null.
     * That is, unless readContentStream() or write() has been called, in which
     * case, the contentStream will have been read, and the content updated.
     * If the class was instantiated with no InputStream, it simply
     * returns the content that was set in the message, or an empty array if no 
     * content was ever set.
     * Message Body from the InputStream
     * @return Returns a byte array containing the message body
     */    
    public byte[] getContent() {
        try {
            byte[] bytes = flushContentStream();
            contentStream = null;
            if (bytes != null) {
                if (content == null) {
                    content = new ByteArrayOutputStream();
                }
                content.write(bytes);
            }
        } catch (IOException ioe) {} // ByteArrayOutputStream can't actually throw an exception
        if (content != null) {
            return content.toByteArray();
        } else {
            return null;
        }
    }
    
    /** returns the bytes that remained in the content stream, or null if contentStream was null
     */    
    private byte[] flushContentStream() {
        if (contentStream != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                byte[] buf = new byte[1024];
                int got = contentStream.read(buf);
                while (got > 0) {
                    baos.write(buf,0, got);
                    got = contentStream.read(buf);
                }
                return baos.toByteArray();
            } catch (IOException ioe) {
                System.out.println("IOException reading from contentStream " + ioe);
            }
        }
        return null;
    }
    
    /** Sets the content of the message body
     * @param content a byte array containing the message body
     */    
    public void setContent(byte[] bytes) {
        // discard whatever is pending in the content stream
        flushContentStream();
        contentStream = null;
        if (bytes != null) {
            content = new ByteArrayOutputStream();
            try {
                content.write(bytes);
            } catch (IOException ioe) {}
        } else {
            content = null;
        }
    }
    
    /** Returns an InputStream that, if read, will return the message body. This is
     * useful to support "straight-through" proxying - read the Request headers, then
     * pipe the request body through to the upstream server, read the Response headers,
     * then pipe the response body through to the browser. No requirement to read the
     * entire body into memory before passing it on to the browser. This speeds up
     * perceived browsing performance.
     * @return An InputStream from which the message body can be read. May be null.
     */    
    public InputStream getContentStream() {
        return contentStream;
    }
    
    /** Allows one to provide a new InputStream from which to read the message body.
     * This could be a "ChunkedInputStream", a "GZipInputStream",
     * etc wrapped around the existing InputStream.
     * @param is The InputStream from which to read the message body.
     */    
    public void setContentStream(InputStream is) {
        content = null;
        contentStream = is;
    }
    
    /** Returns a String representation of the message, *including* the message body.
     * @return The string representation of the message
     */    
    public String toString() {
        return toString("\r\n");
    }
    
    /** Returns a String representation of the message, *including* the message body.
     * Lines of the header are separated by the supplied "CarriageReturnLineFeed" string.
     * @return a String representation of the Message.
     * @param crlf The required line separator string
     */    
    public String toString(String crlf) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            write(baos, crlf);
        } catch (IOException ioe) {}
        return new String(baos.toByteArray());
    }
    
}
