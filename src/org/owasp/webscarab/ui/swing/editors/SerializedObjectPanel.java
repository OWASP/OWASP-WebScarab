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
    }
    
    public String getName() {
        return "SerializedObject";
    }
    
    public String[] getContentTypes() {
        return new String[] { "application/x-serialized-object" };
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        super.setEditable(editable);
    }
    
    public void setBytes(byte[] bytes) {
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
        top.show();
        try {
            sop.setEditable(false);
            sop.setBytes(response.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
