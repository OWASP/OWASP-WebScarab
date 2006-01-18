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
 * SerializedObjectPanel.java
 *
 * Created on 16 November 2003, 05:03
 */

package org.owasp.webscarab.ui.swing.editors;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import javax.swing.JOptionPane;

/**
 *
 * @author  rdawes
 */
public class SerializedObjectPanel extends ObjectPanel implements ByteArrayEditor {
    
    private byte[] _data = new byte[0];
    private boolean _editable = false;
    private boolean _error = false;
    
    /** Creates new form SerializedObjectPanel */
    public SerializedObjectPanel() {
        setName("Serialized Object");
    }
    
    public String[] getContentTypes() {
        return new String[] { "application/x-serialized-object" };
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        super.setEditable(editable);
    }
    
    public void setBytes(String type, byte[] bytes) {
        _data = bytes;
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object o = ois.readObject();
            setObject(o);
            _error = false;
        } catch (IOException ioe) {
            JOptionPane.showMessageDialog(null, "IOException deserializing the byte stream : " + ioe, "IOException", JOptionPane.ERROR_MESSAGE);
            _error = true;
        } catch (ClassNotFoundException cnfe) {
            JOptionPane.showMessageDialog(null, "Class not found while deserializing the byte stream : " + cnfe, "Class not found", JOptionPane.ERROR_MESSAGE);
            _error = true;
        }
        super.setEditable(_editable && !_error);
    }
    
    public byte[] getBytes() {
        if (isModified()) {
            try {
                Object o = getObject();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(o);
                oos.flush();
                baos.flush();
                _data = baos.toByteArray();
            } catch (IOException ioe) {
                System.err.println("Error serialising the object : " + ioe);
                return null;
            }
        }
        return _data;
    }
    
    public static void main(String[] args) {
        org.owasp.webscarab.model.Response response = new org.owasp.webscarab.model.Response();
        try {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            String filename = "c:/temp/2-response";
            if (args.length == 1) {
                filename = args[0];
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(filename);
            response.read(fis);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
        
        javax.swing.JFrame top = new javax.swing.JFrame("Serialized Object Panel");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        
        javax.swing.JButton button = new javax.swing.JButton("GET");
        final SerializedObjectPanel sop = new SerializedObjectPanel();
        top.getContentPane().add(sop);
        top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                System.out.println(new String(sop.getBytes()));
            }
        });
        top.setBounds(100,100,600,400);
        top.setVisible(true);
        try {
            sop.setEditable(false);
            sop.setBytes(null, response.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
