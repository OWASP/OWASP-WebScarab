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
 * HexEditor.java
 *
 * Created on November 4, 2003, 8:23 AM
 */

package org.owasp.webscarab.ui.swing.editors;

import org.owasp.webscarab.model.Preferences;

import javax.swing.AbstractAction;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.Event;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import javax.swing.text.Keymap;
import java.awt.Container;
import javax.swing.JFrame;

import java.io.UnsupportedEncodingException;

/**
 *
 * @author  rdawes
 */
public class TextPanel extends javax.swing.JPanel implements ByteArrayEditor {
    
    private boolean _editable = false;
    private boolean _modified = false;
    
    private byte[] _data = new byte[0];
    
    private SearchDialog _searchDialog = null;
    
    /** Creates new form HexEditor */
    public TextPanel() {
        initComponents();
        setName("Text");
        
        Keymap keymap = JTextArea.addKeymap("MySearchBindings",
                                           textTextArea.getKeymap());
        //Ctrl-f to open the search dialog
        keymap.addActionForKeyStroke(KeyStroke.getKeyStroke(KeyEvent.VK_F, Event.CTRL_MASK), new AbstractAction() {
            public void actionPerformed(ActionEvent event) {
                if (_searchDialog == null) {
                    Container c = textScrollPane;
                    while (! (c instanceof JFrame) && c.getParent() != null) {
                        c = c.getParent();
                    }
                    if (c instanceof JFrame) {
                        _searchDialog = new SearchDialog((JFrame) c, textTextArea);
                    } else {
                        System.err.println("No JFrame parent found!");
                        return;
                    }
                }
                _searchDialog.setVisible(true);
            }
        });
        // Ctrl-G to search again
        keymap.addActionForKeyStroke(KeyStroke.getKeyStroke(KeyEvent.VK_G, Event.CTRL_MASK), new AbstractAction() {
            public void actionPerformed(ActionEvent event) {
                if (_searchDialog != null) {
                    _searchDialog.doSearch();
                }
            }
        });
        // Ctrl-W to search again
        keymap.addActionForKeyStroke(KeyStroke.getKeyStroke(KeyEvent.VK_W, Event.CTRL_MASK), new AbstractAction() {
            public void actionPerformed(ActionEvent event) {
                textTextArea.setLineWrap(! textTextArea.getLineWrap());
            }
        });
        
        textTextArea.setKeymap(keymap);
        
        textTextArea.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent evt) {
		_modified = true;
            }
            public void removeUpdate(DocumentEvent evt) {
		_modified = true;
            }
            public void insertUpdate(DocumentEvent evt) {
		_modified = true;
            }
        });
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        textTextArea.setEditable(editable);
    }
    
    public void setBytes(String contentType, byte[] bytes) {
        if (bytes == null) {
            setText(contentType, "");
        } else {
            try {
                setText(contentType, new String(bytes, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                setText(contentType, e.getMessage());
            }
        }
    }
    
    public void setText(String contentType, String content) {
        String wrap = Preferences.getPreference("TextPanel.wrap", "false");
        if (wrap != null && wrap.equals("true")) textTextArea.setLineWrap(true);
        
        if (content != null) {
            textTextArea.setText(content);
        } else {
            textTextArea.setText("");
        }
        textTextArea.setCaretPosition(0);
        // always set _modified false AFTER setting the text, since the Document listener
        // will set it to true when adding the text
        _modified = false;
    }
    
    public String getText() {
        _modified = false;
        return textTextArea.getText();
    }
    
    public boolean isModified() {
        return _editable && _modified;
    }

    public byte[] getBytes() {
        try {
            return getText().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            System.err.println("This should never happen!");
            return null;
        }
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        textScrollPane = new javax.swing.JScrollPane();
        textTextArea = new javax.swing.JTextArea();

        setLayout(new java.awt.GridBagLayout());

        textTextArea.setEditable(false);
        textScrollPane.setViewportView(textTextArea);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(textScrollPane, gridBagConstraints);

    }//GEN-END:initComponents
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane textScrollPane;
    private javax.swing.JTextArea textTextArea;
    // End of variables declaration//GEN-END:variables
    
    
    public static void main(String[] args) {
        javax.swing.JFrame top = new javax.swing.JFrame("Text Editor");
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        
        TextPanel tp = new TextPanel();
        top.getContentPane().add(tp);
        top.setBounds(100,100,600,400);
        try {
            // tp.setBytes("ABCDEFGHIJKLMNOP\nABCDEFGHIJKLMNOP".getBytes());
            tp.setEditable(true);
            top.setVisible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
        
}
