/*
 * Headers.java
 *
 * Created on May 12, 2003, 10:40 PM
 */

package src.org.owasp.webscarab.model;

import java.util.ArrayList;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;

/** This class represents the headers in either an HTTP Request or Response
 * @author rdawes
 */
public class Header {
    
    private ArrayList headers = null;
    
    /** This class represents the headers in either an HTTP Request or Response */
    public Header() {
    }
    
    /** parses the headers from the supplied InputStream. */    
    protected void read(InputStream is) throws IOException {
        headers = null;
        String line = readLine(is);
        while (!line.equals("")) {
            String[] pair = line.split(": *",2);
            if (pair.length == 2) {
                addHeader(pair[0],pair[1]);
            }
            line = readLine(is);
        }
    }
    
    /** Writes the headers out to the supplied OutputStream */    
    protected void write(OutputStream os) throws IOException {
        write(os,"\r\n");
    }
    
    /** Writes the headers out to the supplied OutputStream, using the supplied string
     * to separate lines.
     */    
    protected void write(OutputStream os, String crlf) throws IOException {
        if (headers == null)
            return;
        for (int i=0; i<headers.size(); i++) {
            String[] row = (String[]) headers.get(i);
            os.write(new String(row[0] + ": " + row[1] + crlf).getBytes());
        }
        
    }
    
    /** sets the value of a header. This overwrites any previous values. */    
    public void setHeader(String name, String value) {
        if (headers == null) {
            headers = new ArrayList(1);
        } else {
            for (int i=0; i<headers.size(); i++) {
                String[] row = (String[]) headers.get(i);
                if (row[0].equalsIgnoreCase(name)) {
                    row[1]=value.trim();
                    headers.set(i,row);
                    return;
                }
            }
        }
        String[] row = new String[] {name, value.trim()};
        headers.add(row);
    }
    
    /** Adds a header with the specified name and value. This preserves any previous 
     * headers with the same name. 
     */
    public void addHeader(String name, String value) {
        if (headers == null) {
            headers = new ArrayList(1);
        }
        String[] row = new String[] {name, value.trim()};
        headers.add(row);
    }
    
    /** Removes a header */    
    public String deleteHeader(String name) {
        if (headers == null) {
            return null;
        }
        for (int i=0; i<headers.size(); i++) {
            String[] row = (String[]) headers.get(i);
            if (row[0].equalsIgnoreCase(name)) {
                headers.remove(i);
                return row[1];
            }
        }
        return null;
    }
    
    /** Returns an array of header names */    
    public String[] getHeaderNames() {
        if (headers == null || headers.size() == 0) {
            return new String[0];
        }
        String[] names = new String[headers.size()];
        for (int i=0; i<headers.size(); i++) {
            String[] row = (String[]) headers.get(i);
            names[i] = row[0];
        }
        return names;
    }
    
    /** Returns the value of the requested header */    
    public String getHeader(String name) {
        if (headers == null) {
            return null;
        }
        for (int i=0; i<headers.size(); i++) {
            String[] row = (String[]) headers.get(i);
            if (row[0].equalsIgnoreCase(name)) {
                return row[1];
            }
        }
        return null;
    }
    
    /** returns the header names and their values */    
    public String[][] getHeaders() {
        if (headers == null || headers.size() == 0) {
            return new String[0][2];
        }
        String[][] table = new String[headers.size()][2];
        for (int i=0; i<headers.size(); i++) {
            String[] row = (String[]) headers.get(i);
            table[i][0] = row[0];
            table[i][1] = row[1];
        }
        return table;
    }
    
    /** sets the headers */    
    public void setHeaders(String[][] table) {
        if (headers == null) {
            headers = new ArrayList(1);
        } else {
            headers.clear();
        }
        for (int i=0; i<table.length; i++) {
            if (table[i].length == 2) {
                setHeader(table[i][0],table[i][1]);
            } else {
                System.out.println("Malformed header table in setHeaders! row " + i);
            }
        }
    }
    
    /** a private method to read a line up to and including the CR or CRLF. Returns the
     * line without the CR or CRLF.
     */    
    protected String readLine(InputStream is) throws IOException {
        String line = new String();
        int i;
        byte[] b={(byte)0x00};
        i = is.read();
        while (i > -1 && i != 10 && i != 13) {
            // Convert the int to a byte
            // we use an array because we can't concat a single byte :-(
            b[0] = (byte)(i & 0xFF);
            String input = new String(b,0,1);
            line = line.concat(input);
            i = is.read();
        }
        if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if we got 13
            i = is.read();
        }
        return line;
    }

    /** returns a string representation of the headers. */    
    public String toString() {
        return toString("\r\n");
    }
    
    /** returns a string representation of the headers. */    
    public String toString(String crlf) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            write(baos, crlf);
        } catch (IOException ioe) {}
        return new String(baos.toByteArray());
    }
    
}
