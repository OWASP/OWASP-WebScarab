/*
 * Response.java
 *
 * Created on May 12, 2003, 11:18 PM
 */

package org.owasp.webscarab.model;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

import java.text.ParseException;

/** Represents a HTTP response as sent by an HTTP server
 * @author rdawes
 */
public class Response extends Message {
    
    private String version = null;
    private String status = null;
    private String message = null;
    private Request _request = null;
    
    /** Creates a new instance of Response */
    public Response() {
    }
    
    /** Creates a new instance of Response, copied from the supplied Response
     * @param resp The original Response to copy
     */    
    public Response(Response resp) {
        this.version = resp.getVersion();
        this.status = resp.getStatus();
        this.message = resp.getMessage();
        setHeaders(resp.getHeaders());
        setContent(resp.getContent());
    }
    
    /** parses the provided InputStream into an HTTP Response. It only parses the header
     * part, and sets the ContentStream to the InputStream at the appropriate point.
     * @param is The InputStream to read the Response from
     */    
    public void read(InputStream is) throws IOException {
        String line = readLine(is);
        if (line == null) {
            throw new IOException("No data received from the server");
        }
        String[] parts = line.split(" ", 3);
        if (parts.length >= 2) {
            setVersion(parts[0]);
            setStatus(parts[1]);
        } else {
            throw new IOException("Invalid response line read from the server: \"" + line + "\"");
        }
        if (parts.length == 3) {
            setMessage(parts[2]);
        } else {
            setMessage("");
        }
        super.read(is);
        if (status.equals("304") || status.equals("204")) {
            // These messages MUST NOT include a body
            setNoBody();
        }
    }
    
    public void parse (String string) throws ParseException {
        parse(new StringBuffer(string));
    }
    
    protected void parse(StringBuffer buff) throws ParseException {
        String line = getLine(buff);
        String[] parts = line.split(" ", 3);
        if (parts.length >= 2) {
            setVersion(parts[0]);
            setStatus(parts[1]);
        }
        if (parts.length == 3) {
            setMessage(parts[2]);
        } else {
            setMessage("");
        }
        super.parse(buff);
        if (status.equals("304") || status.equals("204")) {
            // These messages MUST NOT include a body
            setNoBody();
        }
    }
    
    /** Writes the Response out to the supplied OutputStream, using the HTTP RFC CRLF
     * value of "\r\n"
     */    
    public void write(OutputStream os) throws IOException {
        write(os, "\r\n");
    }
    
    /** Writes the Response to the supplied OutputStream, using the provided CRLF value. */    
    public void write(OutputStream os, String crlf) throws IOException {
        os.write(new String(version + " " + getStatusLine() + crlf).getBytes());
        super.write(os,crlf);
    }
    
    /** Sets the HTTP version supported by the server. */    
    public void setVersion(String version) {
        this.version = version;
    }
    
    /** returns the HTTP version supported by the server */    
    public String getVersion() {
        return version;
    }

    /** sets the status code of the response. */    
    public void setStatus(String status) {
        this.status = status;
    }
    
    /** Gets the status code of the Response. */    
    public String getStatus() {
        return status;
    }
    
    /** sets the human-readable status message */    
    public void setMessage(String message) {
        this.message = message;
    }
    
    /** Gets the human readable status message */    
    public String getMessage() {
        return message;
    }
    
    /** Returns the status code and human readable status message */    
    public String getStatusLine() {
        return status + " " + message;
    }
    
    /** returns a string containing the response, using the RFC specified CRLF of
     * "\r\n" to separate lines.
     */    
    public String toString() {
        return toString("\r\n");
    }
    
    /** returns a string containing the response, using the provided string to separate lines. */    
    public String toString(String crlf) {
        StringBuffer buff = new StringBuffer();
        buff.append(version + " " + getStatusLine() + crlf);
        buff.append(super.toString(crlf));
        return buff.toString();
    }
    
    /** associates this Response with the provided Request */
    public void setRequest(Request request) {
        _request = request;
    }
    
    /** returns the Request that created this Response */
    public Request getRequest() {
        return _request;
    }
        
}
