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
 * ResponsePanel.java
 *
 * Created on 02 June 2003, 03:09
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.SwingUtilities;

import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.ui.swing.editors.TextPanel;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.IOException;
import javax.swing.JFrame;
import javax.swing.JButton;

/**
 *
 * @author  rdawes
 */
public class ResponsePanel extends javax.swing.JPanel {
    
    private boolean[] _upToDate;
    
    private boolean _editable = false;
    private boolean _modified = false;
    
    private int _selected = 0;
    
    private Response _response = null;
    private MessagePanel _messagePanel;
    private TextPanel _textPanel;
    
    private static int _preferred = -1;
    
    /** Creates new form ResponsePanel */
    public ResponsePanel() {
        initComponents();
        
        _messagePanel = new MessagePanel();
        
        parsedPanel.remove(messagePanelPlaceHolder);
        // copy  and paste the constraints for the placeholder from initcomponents
        java.awt.GridBagConstraints gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        parsedPanel.add(_messagePanel, gridBagConstraints);
        
        _textPanel = new TextPanel();
        displayTabbedPane.add("Raw", _textPanel);
        
        setEditable(false);
        _upToDate = new boolean[displayTabbedPane.getTabCount()];
        invalidatePanels();
        
        updateComponents(_editable);
        
        displayTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                updateResponse(_selected);
                _selected = displayTabbedPane.getSelectedIndex();
                _preferred = _selected;
                if (_selected >= 0) {
                    updatePanel(_selected);
                }
            }
        });
        
        if (_preferred > -1 && _preferred < displayTabbedPane.getTabCount()) displayTabbedPane.setSelectedIndex(_preferred);
    }
    
    private void invalidatePanels() {
        for (int i=0; i<_upToDate.length; i++) {
            _upToDate[i] = false;
        }
    }
    
    private void updateResponse(int panel) {
        if (! _editable || panel < 0) {
            return;
        }
        if (displayTabbedPane.getTitleAt(panel).equals("Parsed")) {// parsed text
            if (_messagePanel.isModified()) {
                _response = (Response) _messagePanel.getMessage();
                _modified = true;
                invalidatePanels();
            }
            if (_response == null) {
                _response = new Response();
            }
            // if _modified
            _response.setStatus(statusTextField.getText());
            _response.setMessage(messageTextField.getText());
            _response.setVersion(versionTextField.getText());
        } else if (displayTabbedPane.getTitleAt(panel).equals("Raw")) { // raw text
            if (_textPanel.isModified()) {
                try {
                    Response r = new Response();
                    r.parse(new String(_textPanel.getBytes()));
                    _response = r;
                } catch (Exception e) {
                    System.err.println("Error parsing the rawTextArea, abandoning changes : " + e);
                }
                _modified = true;
                invalidatePanels();
            }
        }
        _upToDate[panel] = true;
    }
    
    public boolean isModified() {
        return _modified;
    }
    
    private void updatePanel(int panel) {
        if (!_upToDate[panel]) {
            if (displayTabbedPane.getTitleAt(panel).equals("Parsed")) {// parsed text
                _messagePanel.setMessage(_response);
                if (_response != null) {
                    statusTextField.setText(_response.getStatus());
                    messageTextField.setText(_response.getMessage());
                    versionTextField.setText(_response.getVersion());
                } else {
                    statusTextField.setText("");
                    messageTextField.setText("");
                    versionTextField.setText("");
                }
            } else if (displayTabbedPane.getTitleAt(panel).equals("Raw")) { // raw text
                if (_response != null) {
                    _textPanel.setText(null, _response.toString("\n"));
                } else {
                    _textPanel.setText(null, "");
                }
            }
            _upToDate[panel] = true;
        }
    }
    
    public void updateComponents(boolean editable) {
        java.awt.Color color;
        if (editable) {
            color = new java.awt.Color(255, 255, 255);
        } else {
            color = new java.awt.Color(204, 204, 204);
        }
        statusTextField.setEditable(editable);
        messageTextField.setEditable(editable);
        versionTextField.setEditable(editable);
        statusTextField.setBackground(color);
        messageTextField.setBackground(color);
        versionTextField.setBackground(color);
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        _textPanel.setEditable(editable);
        _messagePanel.setEditable(editable);
    }
    
    public void setResponse(Response response) {
        _modified = false;
        if (response!= null) {
            _response = new Response(response);
        } else {
            _response = null;
        }
        invalidatePanels();
        if (SwingUtilities.isEventDispatchThread()) {
            updatePanel(displayTabbedPane.getSelectedIndex());
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    updatePanel(displayTabbedPane.getSelectedIndex());
                }
            });
        }
    }
    
    public Response getResponse() {
        if (_editable) {
            int panel = displayTabbedPane.getSelectedIndex();
            updateResponse(panel);
        }
        return _response;
    }
    
    public void selectPanel(String title) {
        for (int i=0; i<displayTabbedPane.getTabCount(); i++) {
            String tab = displayTabbedPane.getTitleAt(i);
            int selected = displayTabbedPane.getSelectedIndex();
            if (tab != null && tab.equalsIgnoreCase(title) && i != selected) {
                displayTabbedPane.setSelectedIndex(i);
                return;
            }
        }
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        displayTabbedPane = new javax.swing.JTabbedPane();
        parsedPanel = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        statusTextField = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        messageTextField = new javax.swing.JTextField();
        messagePanelPlaceHolder = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        versionTextField = new javax.swing.JTextField();

        setLayout(new java.awt.BorderLayout());

        parsedPanel.setLayout(new java.awt.GridBagLayout());

        jLabel3.setLabelFor(statusTextField);
        jLabel3.setText("Status");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        parsedPanel.add(jLabel3, gridBagConstraints);

        statusTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        parsedPanel.add(statusTextField, gridBagConstraints);

        jLabel4.setLabelFor(messageTextField);
        jLabel4.setText("Message");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        parsedPanel.add(jLabel4, gridBagConstraints);

        messageTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.weightx = 1.0;
        parsedPanel.add(messageTextField, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        parsedPanel.add(messagePanelPlaceHolder, gridBagConstraints);

        jLabel5.setLabelFor(messageTextField);
        jLabel5.setText("Version");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        parsedPanel.add(jLabel5, gridBagConstraints);

        versionTextField.setBackground(new java.awt.Color(204, 204, 204));
        versionTextField.setEditable(false);
        versionTextField.setMinimumSize(new java.awt.Dimension(65, 19));
        versionTextField.setPreferredSize(new java.awt.Dimension(65, 19));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        parsedPanel.add(versionTextField, gridBagConstraints);

        displayTabbedPane.addTab("Parsed", parsedPanel);

        add(displayTabbedPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    public static void main(String[] args) {
        final JFrame top = new JFrame("Response Panel");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        final ResponsePanel rp = new ResponsePanel();
        rp.setEditable(false);
        top.getContentPane().add(rp);
        top.setBounds(100,100,800,600);
        top.setVisible(true);
        if (args.length == 0) {
            JButton button = new JButton("NEXT");
            final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
            button.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    loadResponse(top, rp, br);
                }
            });
            loadResponse(top, rp, br);
        } else if (args.length == 1) {
            loadResponse(top, rp, args[0]);
        }
    }
    
    private static void loadResponse(JFrame top, ResponsePanel rp, String file) {
        Response response = new Response();
        try {
            FileInputStream fis = new FileInputStream(file);
            response.read(fis);
            response.flushContentStream();
            fis.close();
        } catch (IOException ioe) {
            System.err.println(file + ": IOException: " + ioe.getMessage());
        }
        rp.setResponse(response);
        top.setTitle(file);
    }
    
    private static void loadResponse(JFrame top, ResponsePanel rp, BufferedReader br) {
        try {
            String file = br.readLine();
            if (file == null) {
                System.exit(0);
            }
            loadResponse(top, rp, file);
        } catch (IOException ioe) {
            System.err.println("IOException: " + ioe.getMessage());
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTabbedPane displayTabbedPane;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel messagePanelPlaceHolder;
    private javax.swing.JTextField messageTextField;
    private javax.swing.JPanel parsedPanel;
    private javax.swing.JTextField statusTextField;
    private javax.swing.JTextField versionTextField;
    // End of variables declaration//GEN-END:variables
    
}
