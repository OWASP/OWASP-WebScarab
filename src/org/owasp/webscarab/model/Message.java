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
import java.util.ArrayList;

import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.owasp.webscarab.httpclient.ChunkedOutputStream;
import org.owasp.webscarab.httpclient.ChunkedInputStream;
import org.owasp.webscarab.httpclient.FixedLengthInputStream;

import java.text.ParseException;

/** Message is a class that is used to represent the bulk of an HTTP message, namely
 * the headers, and (possibly null) body. Messages should not be instantiated
 * directly, but should rather be created by a derived class, namely Request or
 * Response.
 * @author rdawes
 */
public class Message {
    
    private ArrayList _headers = null;
    
    InputStream _contentStream = null;
    byte[] _content = null;
    boolean _chunked = false;
    boolean _gzipped = false;
    int _length = -1;
    
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
        _headers = null;
        String line = readLine(is);
        while (!line.equals("")) {
            String[] pair = line.split(": *",2);
            if (pair.length == 2) {
                addHeader(pair[0],pair[1]);
            }
            line = readLine(is);
        }
        _contentStream = is;
        if (_chunked) {
            _contentStream = new ChunkedInputStream(_contentStream);
        } else if (_length > -1) {
            _contentStream = new FixedLengthInputStream(_contentStream, _length);
        }
    }
    
    /** Writes the Message (headers and content) to the supplied OutputStream */    
    protected void write(OutputStream os) throws IOException {
        write(os, "\r\n");
    }
    
    /** Writes the Message (headers and content) to the supplied OutputStream, using the
     * user supplied string to separate lines.
     */    
    protected void write(OutputStream os, String crlf) throws IOException {
        if (_headers != null) {
            for (int i=0; i<_headers.size(); i++) {
                String[] row = (String[]) _headers.get(i);
                os.write(new String(row[0] + ": " + row[1] + crlf).getBytes());
            }
        }
        os.write(crlf.getBytes());
        if (_chunked) {
            os = new ChunkedOutputStream(os);
        }
        if (_content != null) {
            os.write(_content);
        } else if (_contentStream != null) {
            _content = flushInputStream(_contentStream, os);
            _contentStream = null;
        }
        if (_chunked) {
            ((ChunkedOutputStream) os).writeTrailer();
        }
    }
    
    protected void parse(StringBuffer buffer) throws ParseException {
        _headers = null;
        String line = getLine(buffer);
        while (line != null && !line.equals("")) {
            String[] pair = line.split(": *",2);
            if (pair.length == 2) {
                addHeader(pair[0],pair[1]);
            }
            line = getLine(buffer);
        }
        _content = buffer.toString().getBytes();
        String cl = getHeader("Content-Length");
        if (cl != null) {
            setHeader("Content-Length", Integer.toString(_content.length));
        }
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
        StringBuffer buff = new StringBuffer();
        if (_headers != null) {
            for (int i=0; i<_headers.size(); i++) {
                String[] row = (String[]) _headers.get(i);
                if (row[0].equals("Transfer-Encoding") && row[1].indexOf("chunked")>-1) {
                    buff.append("X-" + row[0] + ": " + row[1] + crlf);
                } else if (row[0].equals("Content-Encoding") && row[1].indexOf("gzip")>-1) {
                    buff.append("X-" + row[0] + ": " + row[1] + crlf);
                } else {
                    buff.append(row[0] + ": " + row[1] + crlf);
                }
            }
        }
        byte[] content = getContent();
        if (_chunked && content != null) {
            buff.append("Content-Length: " + Integer.toString(content.length) + crlf);
        }
        buff.append(crlf);
        if (content != null) {
            try {
                buff.append(new String(content, "UTF-8"));
            } catch (java.io.UnsupportedEncodingException uee) {}; // must support UTF-8
        }
        return buff.toString();
    }
    
    private void updateFlagsForHeader(String name, String value) {
        if (name.equals("Transfer-Encoding")) {
            if (value.indexOf("chunked")>-1) {
                _chunked = true;
            } else {
                _chunked = false;
            }
        } else if (name.equals("Content-Encoding")) {
            if (value.indexOf("gzip")>-1) {
                _gzipped = true;
            } else {
                _gzipped = false;
            }
        } else if (name.equals("Content-Length")) {
            try {
                _length = Integer.parseInt(value);
            } catch (NumberFormatException nfe) {
                System.err.println("Error parsing the content-length '" + value + "' : " + nfe);
            }
        }
    }
    
    /** sets the value of a header. This overwrites any previous values. */    
    public void setHeader(String name, String value) {
        updateFlagsForHeader(name, value);
        if (_headers == null) {
            _headers = new ArrayList(1);
        } else {
            for (int i=0; i<_headers.size(); i++) {
                String[] row = (String[]) _headers.get(i);
                if (row[0].equalsIgnoreCase(name)) {
                    row[1]=value.trim();
                    _headers.set(i,row);
                    return;
                }
            }
        }
        String[] row = new String[] {name, value.trim()};
        _headers.add(row);
    }
    
    /** Adds a header with the specified name and value. This preserves any previous 
     * headers with the same name. 
     */
    public void addHeader(String name, String value) {
        updateFlagsForHeader(name, value);
        if (_headers == null) {
            _headers = new ArrayList(1);
        }
        String[] row = new String[] {name, value.trim()};
        _headers.add(row);
    }
    
    /** Removes a header */    
    public String deleteHeader(String name) {
        if (_headers == null) {
            return null;
        }
        for (int i=0; i<_headers.size(); i++) {
            String[] row = (String[]) _headers.get(i);
            if (row[0].equalsIgnoreCase(name)) {
                _headers.remove(i);
                updateFlagsForHeader(name, "");
                return row[1];
            }
        }
        return null;
    }
    
    /** Returns an array of header names */    
    public String[] getHeaderNames() {
        if (_headers == null || _headers.size() == 0) {
            return new String[0];
        }
        String[] names = new String[_headers.size()];
        for (int i=0; i<_headers.size(); i++) {
            String[] row = (String[]) _headers.get(i);
            names[i] = row[0];
        }
        return names;
    }
    
    /** Returns the value of the requested header */    
    public String getHeader(String name) {
        if (_headers == null) {
            return null;
        }
        for (int i=0; i<_headers.size(); i++) {
            String[] row = (String[]) _headers.get(i);
            if (row[0].equalsIgnoreCase(name)) {
                return row[1];
            }
        }
        return null;
    }
    
    /** returns the header names and their values */    
    public String[][] getHeaders() {
        if (_headers == null || _headers.size() == 0) {
            return new String[0][2];
        }
        String[][] table = new String[_headers.size()][2];
        for (int i=0; i<_headers.size(); i++) {
            String[] row = (String[]) _headers.get(i);
            table[i][0] = row[0];
            table[i][1] = row[1];
        }
        return table;
    }
    
    /** sets the headers */    
    public void setHeaders(String[][] table) {
        if (_headers == null) {
            _headers = new ArrayList();
        } else {
            _headers.clear();
        }
        for (int i=0; i<table.length; i++) {
            if (table[i].length == 2) {
                addHeader(table[i][0],table[i][1]);
            } else {
                System.out.println("Malformed header table in setHeaders! row " + i);
            }
        }
    }
    
    /** a private method to read a line up to and including the CR or CRLF. Returns the
     * line without the CR or CRLF.
     * We don't use a BufferedInputStream so that we don't read further than we should
     * i.e. into the message body, or next message!
     */    
    protected String readLine(InputStream is) throws IOException {
        StringBuffer line = new StringBuffer();
        int i;
        char c=0x00;
        i = is.read();
        if (i == -1) return null;
        while (i > -1 && i != 10 && i != 13) {
            // Convert the int to a char
            c = (char)(i & 0xFF);
            line = line.append(c);
            i = is.read();
        }
        if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if we got 13
            i = is.read();
        }
        return line.toString();
    }
    
    /** a private method to read a line up to and including the CR or CRLF. Returns the
     * line without the CR or CRLF. Deletes the line from the supplied StringBuffer.
     */    
    protected String getLine(StringBuffer buffer) {
        int lf = buffer.indexOf("\n");
        if (lf > -1) {
            int cr = buffer.indexOf("\r");
            if (cr == -1 || cr > lf) {
                cr = lf;
            }
            String line = buffer.substring(0,cr);
            buffer.delete(0, lf+1);
            System.err.println("line is '" + line + "'");
            return line;
        } else if (buffer.length() > 0) {
            String line = buffer.toString();
            buffer.setLength(0);
            System.err.println("line is '" + line + "'");
            return line;
        } else {
            return null;
        }
    }
    
    public int getContentLength() {
        if (_contentStream != null) {
            _content = flushInputStream(_contentStream, null);
            _contentStream = null;
        }
        if (_content != null) {
            return _content.length;
        } else {
            return -1;
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
        if (_contentStream != null) {
            _content = flushInputStream(_contentStream, null);
            _contentStream = null;
        }
        if (_content != null && _gzipped) {
            try {
                GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(_content));
                return flushInputStream(gzis, null);
            } catch (IOException ioe) {
                System.err.println("IOException unzipping content : " + ioe);
                return null;
            }
        }
        return _content;
    }
    
    /** reads all the remaining bytes into the "content" byte array, optionally
     *  writing them to the provided output stream as well
     */    
    private byte[] flushInputStream(InputStream is, OutputStream os) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            byte[] buf = new byte[1024];
            int got = is.read(buf);
            while (got > 0) {
                baos.write(buf,0, got);
                if (os != null) {
                    os.write(buf,0,got);
                }
                got = is.read(buf);
            }
        } catch (IOException ioe) {
            System.out.println("IOException flushing inputStream " + ioe);
        }
        return baos.toByteArray();
    }
    
    public void setNoBody() {
        _content = null;
        _contentStream = null;
    }
    
    /** Sets the content of the message body
     * @param content a byte array containing the message body
     */    
    public void setContent(byte[] bytes) {
        // discard whatever is pending in the content stream
        if (_contentStream != null) {
            flushInputStream(_contentStream, null);
            _contentStream = null;
        }
        if (_gzipped && bytes != null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                GZIPOutputStream gzos = new GZIPOutputStream(baos);
                gzos.write(bytes);
                gzos.close();
                _content = baos.toByteArray();
            } catch (IOException ioe) {
                System.err.println("IOException gzipping content : " + ioe);
            }
        } else {
            _content = bytes;
        }
    }
        
}
