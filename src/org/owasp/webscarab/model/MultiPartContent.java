/*
 * MultiPartPanel.java
 *
 * Created on 16 December 2004, 05:08
 */

package org.owasp.webscarab.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

import java.io.UnsupportedEncodingException;

/**
 *
 * @author  rogan
 */
public class MultiPartContent {
    
    private byte[] _boundary;
    private List<Message> _parts;
    
    private static final byte[] CRLF = new byte[] { '\r', '\n' };
    
    /** Creates a new instance of MultiPartContent */
    public MultiPartContent(String contentType, byte[] content) {
        try {
            _parts = new ArrayList<Message>();
            if (contentType != null && contentType.trim().startsWith("multipart/form-data")) {
                int pos = contentType.indexOf("boundary=");
                int semi = contentType.indexOf(";", pos);
                if (semi < 0) semi = contentType.length();
                _boundary = ("--" + contentType.substring(pos+9,semi).trim()).getBytes("UTF-8");
            } else {
                _boundary = null;
            }
            if (_boundary != null) {
                int start = findBytes(content, _boundary, 0) + _boundary.length + CRLF.length;
                int end = findBytes(content, _boundary, start);
                while (end < content.length) {
                    Message message = new Message();
                    try {
                        message.read(new ByteArrayInputStream(content, start, end-start-CRLF.length));
                    } catch (IOException ioe) {
                        System.err.println("IOException on a ByteArrayInputStream should never happen! " + ioe);
                    }
                    _parts.add(message);
                    start = end + _boundary.length + CRLF.length;
                    end = findBytes(content, _boundary, start);
                }
            }
        } catch (UnsupportedEncodingException e) {
            System.err.println("UTF-8 not supported?! " + e);
        }
    }
    
    public boolean verifyBoundary() {
        return true;
    }
    
    public String getBoundary() {
        try {
            return new String(_boundary, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            System.err.println("UTF-8 not supported?! " + e);
            return null;
        }
    }
    
    public int size() {
        return _parts.size();
    }
    
    public Message set(int index, Message part) {
        return (Message) _parts.set(index, part);
    }
    
    public Message get(int index) {
        return (Message) _parts.get(index);
    }
    
    public Message remove(int index) {
        return (Message) _parts.remove(index);
    }
    
    public void add(int index, Message part) {
        _parts.add(index, part);
    }
    
    public boolean add(Message part) {
        return _parts.add(part);
    }
    
    private int findBytes(byte[] source, byte[] find, int start) {
        int matches = 0;
        int pos = start;
        while (pos<source.length && matches < find.length) {
            if (source[pos+matches] == find[matches]) {
                matches++;
            } else {
                matches = 0;
                pos++;
            }
        }
        return pos;
    }
    
    public String getPartName(int index) {
        Message part = (Message) _parts.get(index);
        String disposition = part.getHeader("Content-Disposition");
        int nameindex = disposition.indexOf("name=");
        int semi = disposition.indexOf(";", nameindex);
        if (semi<0) semi = disposition.length();
        String name = disposition.substring(nameindex+5,semi).trim();
        if (name.startsWith("\"") && name.endsWith("\"") || name.startsWith("\"") && name.endsWith("\"")) {
            name = name.substring(1,name.length()-1);
        }
        return name;
    }
    
    public byte[] getBytes() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(_boundary);
            baos.write(CRLF);
            Iterator<Message> it = _parts.iterator();
            while (it.hasNext()) {
                Message message = (Message) it.next();
                message.write(baos);
                baos.write(CRLF);
                baos.write(_boundary);
                baos.write(CRLF);
            }
            return baos.toByteArray();
        } catch (IOException ioe) {
            System.err.println("Shouldn't happen!! " + ioe);
        }
        return null;
    }
    
    public static void main(String[] args) {
        Request request = new Request();
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream("/home/rogan/csob/3/conversations/4-request");
            request.read(fis);
            MultiPartContent mpc = new MultiPartContent(request.getHeader("Content-Type"), request.getContent());
            System.out.println("Got " + mpc.size());
            Message message = mpc.get(0);
            System.out.println("First part is " + message.getHeader("Content-Disposition") + " = '" + new String(message.getContent()) + "'");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
