/*
 * Request.java
 *
 * Created on May 12, 2003, 11:12 PM
 */

package org.owasp.webscarab.model;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.MalformedURLException;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;

import org.owasp.webscarab.util.Util;

/** This class represents a request that can be sent to an HTTP server.
 * @author rdawes
 */
public class Request extends Message {
    
    private String method = null;
    private URL url = null;
    private String version = null;
    InputStream is = null;
    private String _base = null;
    
    /** Creates a new instance of Request */
    public Request() {
    }
    
    /** Creates a new Request, which is a copy of the supplied Request */    
    public Request(Request req) {
        this.method = req.getMethod();
        this.url = req.getURL();
        this.version = req.getVersion();
        setHeaders(req.getHeaders());
        setContent(req.getContent());
    }
        
    /** initialises the Request from the supplied InputStream */    
    public void read(InputStream is) throws IOException {
        this.is = is;
        String line = readLine(is);
        String[] parts = line.split(" ");
        if (parts.length == 0) {
            System.err.println("Empty request!");
        } else if (parts.length == 2 || parts.length == 3) {
            setMethod(parts[0]);
            if (getMethod().equalsIgnoreCase("CONNECT")) {
                setURL("https://" + parts[1] + "/");
            } else {
                setURL(parts[1]);
            }
        } else {
            throw new IOException("Invalid request line reading from the InputStream");
        }
        if (parts.length == 3) {
            setVersion(parts[2]);
        } else {
            setVersion("HTTP/0.9");
        }
        super.read(is);
        if (method.equals("CONNECT") || method.equals("GET")) {
            // These methods cannot include a body
            setContentStream(null);
            setContent(null);
        }
    }
    
    /** Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to an HTTP proxy. Uses the RFC CRLF string "\r\n"
     */    
    public void write(OutputStream os) throws IOException {
        write(os,"\r\n");
    }
    
    /** Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to an HTTP proxy. Uses the supplied string to separate lines.
     */    
    public void write(OutputStream os, String crlf) throws IOException {
        os.write(new String(method+" "+(url==null?"null":url.getProtocol()) + "://" + (url==null?"null":url.getHost())).getBytes());
        os.write(new String(":"+(url==null?"null":String.valueOf(url.getPort()==-1?url.getDefaultPort():url.getPort()))).getBytes());
        os.write(new String((url==null?"null":url.getPath())).getBytes());
        os.write(new String((url==null?"null":url.getQuery()==null?"":"?"+url.getQuery())).getBytes());
        os.write(new String(" " + version + crlf).getBytes());
        super.write(os, crlf);
    }
    
    /** Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to the HTTP server itself. Uses the RFC CRLF string "\r\n"
     */    
    public void writeDirect(OutputStream os) throws IOException {
        writeDirect(os, "\r\n");
    }
    
    /** Writes the Request to the supplied OutputStream, in a format appropriate for
     * sending to the HTTP server itself. Uses the supplied string to separate lines.
     */    
    public void writeDirect(OutputStream os, String crlf) throws IOException {
        os.write(new String(method+" " + (url==null?"null":url.getPath())).getBytes());
        os.write(new String((url==null?"null":url.getQuery()==null?"":"?"+url.getQuery())).getBytes());
        os.write(new String(" " + version + crlf).getBytes());
        super.write(os, crlf);
    }
    
    /** Sets the request method */    
    public void setMethod(String method) {
        this.method = method;
    }
    
    /** gets the Request method */    
    public String getMethod() {
        return method;
    }
    
    /** Sets the URL that the URL read from the InputStream should be based on. This is
     * appropriate when parsing an intercepted CONNECT Request, when the URL read will
     * no longer include the protocol://host:port.
     */    
    public void setBaseURL(String base) {
        _base = base;
    }
    
    /** Sets the Request URL */    
    public void setURL(String url) throws MalformedURLException {
        if (_base != null) {
            this.url = new URL(_base + url);
        } else {
            this.url = new URL(url);
        }
    }
    
    /** Sets the Request URL */    
    public void setURL(URL url) {
        this.url = url;
    }
    
    /** Gets the Request URL */    
    public URL getURL() {
        return url;
    }
    
    /** Sets the HTTP version supported */    
    public void setVersion(String version) {
        this.version = version;
    }
    
    /** gets the HTTP version */    
    public String getVersion() {
        return version;
    }
    
    /** returns a string representation of the Request, using a CRLF of "\r\n" */    
    public String toString() {
        return toString("\r\n");
    }
    
    /** returns a string representation of the Request, using the supplied string to
     * separate lines
     */    
    public String toString(String crlf) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            write(baos, crlf);
        } catch (IOException ioe) {}
        return new String(baos.toByteArray());
    }
    
    public String[][] getParameters() {
        ArrayList params = new ArrayList(1);
        String s;
        if (url == null) { return new String[0][0]; }
        String query;
        if ((query=Util.getURLQuery(url)) != null) {
            String[] frags = null;
            String[] queries = null;
            if (query != null && query.startsWith(";")) {
                String[] pq = query.split("\\?",2);
                frags = pq[0].substring(1).split(";");
                if (pq.length>1) {
                    queries = pq[1].split("\\&");
                }
            } else if (query != null && query.startsWith("?")) {
                queries = query.substring(1).split("&");
            }
            if (frags != null && frags.length>0) {
                for (int i=0; i< frags.length; i++) {
                    if (frags[i].length() > 0) {
                        String[] pair = frags[i].split("=");
                        String[] row = new String[] {"FRAGMENT",pair[0], pair[1]};
                        params.add(row);
                    }
                }
            }
            if (queries != null && queries.length > 0) {
                for (int i=0; i<queries.length; i++) {
                    String[] pair = queries[i].split("=");
                    if (pair.length == 2) {
                        String[] row = new String[] {"QUERY",pair[0],pair[1]};
                        params.add(row);
                    } else {
                        String[] row = new String[] {"QUERY",pair[0],new String("")};
                        params.add(row);
                    }                        
                }
            }
        }
        String cookie = getHeader("Cookie");
        if (cookie != null) {
            // Add the cookie
            String[] cookies = cookie.split(" *; *");
            for (int i=0; i<cookies.length; i++) {
                String[] pair = cookies[i].split("=");
                String[] row = new String[] {"COOKIE", pair[0], pair[1]};
                params.add(row);
            }
        }
        if (getContent() != null) {
            String content = new String(getContent());
            String[] body = content.split("&");
            for (int i=0; i< body.length; i++) {
                String[] pair = body[i].split("=");
                if (pair.length == 2) {
                    String[] row = new String[] {"BODY",pair[0],pair[1]};
                    params.add(row);
                } else {
                    String[] row = new String[] {"BODY",pair[0],new String("")};
                    params.add(row);
                }                    
            }
        }
        String[][] p = new String[params.size()][3];
        for (int i=0; i<params.size(); i++) {
            p[i]=(String[])params.get(i);
        }
        return p;
    }
    
    public void setParameters(String[][] params) {
        String fragment = null;
        String query = null;
        String cookie = null;
        String content = null;
        
        for (int i=0; i<params.length; i++) {
            String type = params[i][0];
            String name = params[i][1];
            String value = params[i][2];
            if (value == null) value = "";
            if (type.equals("FRAGMENT")) {
                if (fragment == null) {
                    fragment = new String(name + "=" + value);
                } else {
                    System.err.println("Not sure if an URL is permitted to have multiple fragments. Currently '" 
                    + fragment + "', adding " + name + "=" + value);
                    fragment = fragment + "&" + name + "=" + value;
                }
            } else if (type.equals("QUERY")) {
                if (query == null)
                    query = new String(name + "=" + value);
                else
                    query = query + "&" + name + "=" + value;
            } else if (type.equals("COOKIE")) {
                if (cookie == null) {
                    cookie = new String(name + "=" + value);
                } else {
                    cookie = cookie + "; " + name + "=" + value;
                }
            } else if (type.equals("BODY")) {
                if (content == null)
                    content = new String(name + "=" + value);
                else
                    content = content + "&" + name + "=" + value;
            }
        }
        String fragquery = new String("");
        try {
            if (fragment != null) {
                fragquery = ";" + fragment;
            }
            if (query != null) {
                fragquery = fragquery + "?" + query;
            }
            if (!fragquery.equals("")) {
                url = new URL(Util.getURLSHPP(url) + fragquery);
            }
        } catch (MalformedURLException mue) {
            System.err.println("Error creating the URL with fragquery '" + fragquery + "' : " + mue);
            return;
        }
        if (cookie != null) {
            setHeader("Cookie", cookie);
        } else {
            deleteHeader("Cookie");
        }
        if (content != null) {
            if (!method.equalsIgnoreCase("GET")) {
                setContent(content.getBytes());
                setHeader("Content-Length",Integer.toString(content.length()));
            } else {
                System.err.println("GET does not support BODY parameters");
            }
        } else {
            setContent(null);
            deleteHeader("Content-Length");
        }
    }

}
