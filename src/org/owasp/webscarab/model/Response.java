/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * Response.java
 *
 * Created on May 12, 2003, 11:18 PM
 */

package org.owasp.webscarab.model;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;

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
        setVersion("HTTP/1.0");
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
    
    /**
     * parses the provided InputStream into an HTTP Response. It only parses the header
     * part, and sets the ContentStream to the InputStream at the appropriate point.
     * @param is The InputStream to read the Response from
     * @throws IOException propagated from the InputStream
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
    
    /**
     * parses a Response from the String provided
     * @param string
     * @throws ParseException
     */    
    public void parse (String string) throws ParseException {
        parse(new StringBuffer(string));
    }
    
    /**
     *
     * @param buff
     * @throws ParseException
     */    
    public void parse(StringBuffer buff) throws ParseException {
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
    
    /**
     * Writes the Response out to the supplied OutputStream, using the HTTP RFC CRLF
     * value of "\r\n"
     * @param os
     * @throws IOException
     */    
    public void write(OutputStream os) throws IOException {
        write(os, "\r\n");
    }
    
    /**
     * Writes the Response to the supplied OutputStream, using the provided CRLF value.
     * @param os
     * @param crlf
     * @throws IOException
     */    
    public void write(OutputStream os, String crlf) throws IOException {
        os = new BufferedOutputStream(os);
        os.write(new String(version + " " + getStatusLine() + crlf).getBytes());
        super.write(os,crlf);
        os.flush();
    }
    
    /**
     * Sets the HTTP version supported by the server.
     * @param version
     */    
    public void setVersion(String version) {
        this.version = version;
    }
    
    /**
     * returns the HTTP version supported by the server
     * @return
     */    
    public String getVersion() {
        return version;
    }

    /**
     * sets the status code of the response.
     * @param status
     */    
    public void setStatus(String status) {
        this.status = status;
    }
    
    /**
     * Gets the status code of the Response.
     * @return
     */    
    public String getStatus() {
        return status;
    }
    
    /**
     * sets the human-readable status message
     * @param message
     */    
    public void setMessage(String message) {
        this.message = message;
    }
    
    /**
     * Gets the human readable status message
     * @return
     */    
    public String getMessage() {
        return message;
    }
    
    /**
     * Returns the status code and human readable status message
     * @return
     */    
    public String getStatusLine() {
        return status + " " + message;
    }
    
    /**
     * returns a string containing the response, using the RFC specified CRLF of
     * "\r\n" to separate lines.
     * @return
     */    
    public String toString() {
        return toString("\r\n");
    }
    
    /**
     * returns a string containing the response, using the provided string to separate lines.
     * @param crlf
     * @return
     */    
    public String toString(String crlf) {
        StringBuffer buff = new StringBuffer();
        buff.append(version + " " + getStatusLine() + crlf);
        buff.append(super.toString(crlf));
        return buff.toString();
    }
    
    /**
     * associates this Response with the provided Request
     * @param request
     */
    public void setRequest(Request request) {
        _request = request;
    }
    
    /**
     * returns the Request that created this Response
     * @return the request
     */
    public Request getRequest() {
        return _request;
    }
        
    public boolean equals(Object obj) {
        if (! (obj instanceof Response)) return false;
        Response resp = (Response) obj;
        if (!getVersion().equals(resp.getVersion())) return false;
        if (!getStatusLine().equals(resp.getStatusLine())) return false;
        return super.equals(obj);
    }
    
}
