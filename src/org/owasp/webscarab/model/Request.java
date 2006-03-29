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
 * Request.java
 *
 * Created on May 12, 2003, 11:12 PM
 */

package org.owasp.webscarab.model;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;

import java.text.ParseException;
import java.util.logging.Level;

/** This class represents a request that can be sent to an HTTP server.
 * @author rdawes
 */
public class Request extends Message {
    
    private String _method = "GET";
    private HttpUrl _url = null;
    private String _version = "HTTP/1.0";
    
    /** Creates a new instance of Request */
    public Request() {
    }
    
    /**
     * Creates a new Request, which is a copy of the supplied Request
     * @param req the request to copy
     */    
    public Request(Request req) {
        _method = req.getMethod();
        _url = req.getURL();
        _version = req.getVersion();
        setHeaders(req.getHeaders());
        setContent(req.getContent());
    }
    
    /**
     * initialises the Request from the supplied InputStream
     * @param is the InputStream to read from
     * @throws IOException propagates any exceptions thrown by the InputStream
     */
    public void read(InputStream is) throws IOException {
        read(is, null);
    }
    
    /**
     * initialises the Request from the supplied InputStream, using the supplied Url
     * as a base. This will generally be useful where we are acting as a web server,
     * and reading a line like "GET / HTTP/1.0". The request Url is then created
     * relative to the supplied Url.
     * @param is the InputStream to read from
     * @param base the base Url to use for relative Urls
     * @throws IOException propagates any IOExceptions thrown by the InputStream
     */    
    public void read(InputStream is, HttpUrl base) throws IOException {
        String line = null;
        _logger.finer("Base: " + base);
        try {
            line = readLine(is);
            _logger.finest("Request: " + line);
        } catch (SocketTimeoutException ste) {
            // System.err.println("Read timed out. Closing connection");
            return;
        }
        if (line == null || line.equals("")) {
            // System.err.println("Client closed connection!");
            return;
        }
        String[] parts = line.split(" ");
        if (parts.length == 2 || parts.length == 3) {
            setMethod(parts[0]);
            if (getMethod().equalsIgnoreCase("CONNECT")) {
                setURL(new HttpUrl("https://" + parts[1] + "/"));
            } else {
                // supports creating an absolute url from a relative one
                setURL(new HttpUrl(base, parts[1]));
            }
        } else {
            throw new IOException("Invalid request line reading from the InputStream '"+line+"'");
        }
        if (parts.length == 3) {
            setVersion(parts[2]);
        } else {
            setVersion("HTTP/0.9");
        }
        // Read the rest of the message headers and to the start of the body
        super.read(is);
        if (_method.equals("CONNECT") || _method.equals("GET") || _method.equals("HEAD") || _method.equals("TRACE")) {
            // These methods cannot include a message body
            setNoBody();
        }
    }
    
    /**
     * parses a string representation of a request
     * @param string the string representing the request
     * @throws ParseException if there are any errors parsing the request
     */    
    public void parse(String string) throws ParseException {
        parse(new StringBuffer(string));
    }
    
    /**
     * parses a string representation of a request
     * @param buff a StringBuffer containing the request. Note that the contents of the StringBuffer are consumed during parsing.
     * @throws ParseException if there are any errors parsing the request
     */    
    public void parse(StringBuffer buff) throws ParseException {
        String line = null;
        line = getLine(buff);
        String[] parts = line.split(" ");
        if (parts.length == 2 || parts.length == 3) {
            setMethod(parts[0]);
            try {
                if (getMethod().equalsIgnoreCase("CONNECT")) {
                    setURL(new HttpUrl("https://" + parts[1] + "/"));
                } else {
                    setURL(new HttpUrl(parts[1]));
                }
            } catch (MalformedURLException mue) {
                throw new ParseException("Malformed URL '" + parts[1] + "' : " + mue, parts[0].length()+1);
            }
        } else {
            throw new ParseException("Invalid request line '" + line + "'", 0);
        }
        if (parts.length == 3) {
            setVersion(parts[2]);
        } else {
            setVersion("HTTP/0.9");
        }
        // Read the rest of the message headers and body
        super.parse(buff);
        if (_method.equals("CONNECT") || _method.equals("GET") || _method.equals("HEAD") || _method.equals("TRACE")) {
            // These methods cannot include a message body
            setNoBody();
        }
    }
    
    /**
     * Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to an HTTP proxy. Uses the RFC CRLF string "\r\n"
     * @param os the OutputStream to write to
     * @throws IOException if the underlying stream throws any.
     */    
    public void write(OutputStream os) throws IOException {
        write(os,"\r\n");
    }
    
    /**
     * Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to an HTTP proxy. Uses the supplied string to separate lines.
     * @param os the OutputStream to write to
     * @param crlf the string to use to separate the lines (usually a CRLF pair)
     * @throws IOException if the underlying stream throws any.
     */    
    public void write(OutputStream os, String crlf) throws IOException {
        if (_method == null || _url == null || _version == null) {
            System.err.println("Uninitialised Request!");
            return;
        }
        os = new BufferedOutputStream(os);
        String requestLine = _method+" "+_url+" " + _version + crlf;
        os.write(requestLine.getBytes());
        _logger.finer("Request: " + requestLine);
        super.write(os, crlf);
        os.flush();
    }
    
    /** Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to the HTTP server itself. Uses the RFC CRLF string "\r\n"
     * @param os the OutputStream to write to
     * @throws IOException if the underlying stream throws any.
     */    
    public void writeDirect(OutputStream os) throws IOException {
        writeDirect(os, "\r\n");
    }
    
    /** Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to the HTTP server itself. Uses the supplied string to separate lines.
     * @param os the OutputStream to write to
     * @param crlf the string to use to separate the lines (usually a CRLF pair)
     * @throws IOException if the underlying stream throws any.
     */    
    public void writeDirect(OutputStream os, String crlf) throws IOException {
        if (_method == null || _url == null || _version == null) {
            System.err.println("Uninitialised Request!");
            return;
        }
        os = new BufferedOutputStream(os);
        String requestLine = _method + " " + _url.direct() + " " + _version;
        os.write((requestLine+crlf).getBytes());
        _logger.finer("Request: " + requestLine);
        super.write(os, crlf);
        os.flush();
    }
    
    /**
     * Sets the request method
     * @param method the method of the request (automatically converted to uppercase)
     */    
    public void setMethod(String method) {
        _method = method.toUpperCase();
    }
    
    /**
     * gets the Request method
     * @return the request method
     */    
    public String getMethod() {
        return _method;
    }
    
    /**
     * Sets the Request URL
     * @param url the url
     */    
    public void setURL(HttpUrl url) {
        _url = url;
    }
    
    /**
     * Gets the Request URL
     * @return the request url
     */    
    public HttpUrl getURL() {
        return _url;
    }
    
    /**
     * Sets the HTTP version supported
     * @param version the version of the request. Automatically converted to uppercase.
     */    
    public void setVersion(String version) {
        _version = version.toUpperCase();
    }
    
    /**
     * gets the HTTP version
     * @return the version of the request
     */    
    public String getVersion() {
        return _version;
    }
    
    /**
     * returns a string representation of the Request, using a CRLF of "\r\n"
     * @return a string representation of the Request, using a CRLF of "\r\n"
     */    
    public String toString() {
        return toString("\r\n");
    }
    
    /**
     * returns a string representation of the Request, using the supplied string to
     * separate lines
     * @param crlf the string to use to separate lines (usually CRLF)
     * @return a string representation of the Request
     */    
    public String toString(String crlf) {
        if (_method == null || _url == null || _version == null) {
            return "Unitialised Request!";
        }
        StringBuffer buff = new StringBuffer();
        buff.append(_method).append(" ");
        buff.append(_url).append(" ");
        buff.append(_version).append(crlf);
        buff.append(super.toString(crlf));
        return buff.toString();
    }
    
    public boolean equals(Object obj) {
        if (!(obj instanceof Request)) return false;
        Request req = (Request)obj;
        if (!getMethod().equals(req.getMethod())) return false;
        if (!getURL().equals(req.getURL())) return false;
        if (!getVersion().equals(req.getVersion())) return false;
        return super.equals(req);
    }
    
}
