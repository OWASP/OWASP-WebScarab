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

/** Represents a HTTP response as sent by an HTTP server
 * @author rdawes
 */
public class Response extends Message implements Cloneable {
    
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
        super.read(is);
        if (status.startsWith("1") || status.equals("304") || status.equals("204")) {
            // These messages MUST NOT include a body
            setContentStream(null);
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
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            write(baos, crlf);
        } catch (IOException ioe) {}
        return new String(baos.toByteArray());
    }
    
    /** associates this Response with the provided Request */
    public void setRequest(Request request) {
        _request = request;
    }
    
    /** returns the Request that created this Response */
    public Request getRequest() {
        return _request;
    }
    
    public Object clone() throws CloneNotSupportedException {
        Response copy = (Response) super.clone();
        return copy;
    }
    
}
