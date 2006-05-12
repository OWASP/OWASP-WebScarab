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
 * RequestPanel.java
 *
 * Created on 02 June 2003, 03:09
 */

package org.owasp.webscarab.ui.swing;

import java.net.MalformedURLException;
import javax.swing.JOptionPane;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.SwingUtilities;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.ui.swing.editors.TextPanel;

import java.awt.Component;

import java.util.logging.Logger;

/**
 *
 * @author  rdawes
 */
public class RequestPanel extends javax.swing.JPanel {
    
    private boolean[] _upToDate;
    
    private boolean _editable = false;
    private boolean _modified = false;
    
    private int _selected = 0;
    
    private Request _request = null;
    private MessagePanel _messagePanel;
    private TextPanel _textPanel;
    
    private static int _preferred = -1;
    private boolean _reverting = false;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates new form RequestPanel */
    public RequestPanel() {
        initComponents();
        
        displayTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                try {
                    updateRequest(_selected);
                    _selected = displayTabbedPane.getSelectedIndex();
                    _preferred = _selected;
                    if (_selected >= 0) {
                        updatePanel(_selected);
                    }
                } catch (MalformedURLException mue) {
                    if (!_reverting) {
                        JOptionPane.showMessageDialog(RequestPanel.this, new String[] {"The URL requested is malformed", mue.getMessage()}, "Malformed URL", JOptionPane.ERROR_MESSAGE);
                        _reverting = true;
                        displayTabbedPane.setSelectedIndex(_selected);
                        _reverting = false;
                    }
                }
            }
        });

        _messagePanel = new MessagePanel();

        parsedPanel.remove(messagePanelPlaceHolder);
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
        
        _upToDate = new boolean[displayTabbedPane.getTabCount()];
        invalidatePanels();
        
        updateComponents(_editable);
        
        if (_preferred > -1 && _preferred < displayTabbedPane.getTabCount()) displayTabbedPane.setSelectedIndex(_preferred);
    }
    
    private void invalidatePanels() {
        for (int i=0; i<_upToDate.length; i++) {
            _upToDate[i] = false;
        }
    }
    
    private void updateRequest(int panel) throws MalformedURLException {
        if (! _editable || panel < 0) {
            return;
        }
        if (displayTabbedPane.getTitleAt(panel).equals("Parsed")) {// parsed text
            if (_messagePanel.isModified()) {
                _request = (Request) _messagePanel.getMessage();
                _modified = true;
            }
            if (_request == null) {
                _request = new Request();
            }
            _request.setMethod(methodTextField.getText());
            String url = urlTextField.getText();
            if (!"".equals(url))
                _request.setURL(new HttpUrl(url));
            _request.setVersion(versionTextField.getText());
            // this is a bit of a hack. What we should really do is add a listener
            // to the text fields, so we know when a change has been made. Until then
            // this will do
            _modified = true;
        } else if (displayTabbedPane.getTitleAt(panel).equals("Raw")) { // raw text
            if (_textPanel.isModified()) {
                try {
                    Request r = new Request();
                    String text = _textPanel.getText();
                    if (!"".equals(text))
                        r.parse(_textPanel.getText());
                    _request = r;
                } catch (Exception e) {
                    _logger.severe("Error parsing the rawTextArea, abandoning changes : " + e);
                }
                _modified = true;
            }
        }
        if (_modified)
            invalidatePanels();
        _upToDate[panel] = true;
    }
    
    public boolean isModified() {
        return _modified;
    }
    
    private void updatePanel(int panel) {
        if (!_upToDate[panel]) {
            if (displayTabbedPane.getTitleAt(panel).equals("Parsed")) {// parsed text
                _messagePanel.setMessage(_request);
                if (_request != null) {
                    methodTextField.setText(_request.getMethod());
                    if (_request.getURL() != null) {
                        urlTextField.setText(_request.getURL().toString());
                    } else {
                        urlTextField.setText("");
                    }
                    versionTextField.setText(_request.getVersion());
                } else {
                    methodTextField.setText("");
                    urlTextField.setText("");
                    versionTextField.setText("");
                }
            } else if (displayTabbedPane.getTitleAt(panel).equals("Raw")) { // raw text
                if (_request != null && _request.getMethod() != null && _request.getURL() != null && _request.getVersion() != null) {
                    _textPanel.setText(null, _request.toString("\n"));
                } else {
                    _textPanel.setText(null, "");
                }
            }
            _upToDate[panel] = true;
        }
    }
    
    private void updateComponents(boolean editable) {
        java.awt.Color color;
        if (editable) {
            color = new java.awt.Color(255, 255, 255);
        } else {
            color = new java.awt.Color(204, 204, 204);
        }
        methodTextField.setEditable(editable);
        urlTextField.setEditable(editable);
        versionTextField.setEditable(editable);
        methodTextField.setBackground(color);
        urlTextField.setBackground(color);
        versionTextField.setBackground(color);
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        _textPanel.setEditable(editable);
        updateComponents(editable);
        _messagePanel.setEditable(editable);
    }
    
    public void setRequest(Request request) {
        _modified = false;
        if (request != null) {
            _request = new Request(request);
        } else {
            _request = null;
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
    
    public Request getRequest() throws MalformedURLException {
        if (_editable) {
            int panel = displayTabbedPane.getSelectedIndex();
            updateRequest(panel);
        }
        return _request;
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
        methodTextField = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        urlTextField = new javax.swing.JTextField();
        messagePanelPlaceHolder = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        versionTextField = new javax.swing.JTextField();

        setLayout(new java.awt.BorderLayout());

        parsedPanel.setLayout(new java.awt.GridBagLayout());

        jLabel3.setLabelFor(methodTextField);
        jLabel3.setText("Method");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        parsedPanel.add(jLabel3, gridBagConstraints);

        methodTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        parsedPanel.add(methodTextField, gridBagConstraints);

        jLabel4.setLabelFor(urlTextField);
        jLabel4.setText("URL");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        parsedPanel.add(jLabel4, gridBagConstraints);

        urlTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        parsedPanel.add(urlTextField, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        parsedPanel.add(messagePanelPlaceHolder, gridBagConstraints);

        jLabel5.setLabelFor(urlTextField);
        jLabel5.setText("Version");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        parsedPanel.add(jLabel5, gridBagConstraints);

        versionTextField.setBackground(new java.awt.Color(204, 204, 204));
        versionTextField.setEditable(false);
        versionTextField.setText("HTTP/1.0");
        versionTextField.setMinimumSize(new java.awt.Dimension(65, 19));
        versionTextField.setPreferredSize(new java.awt.Dimension(65, 19));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        parsedPanel.add(versionTextField, gridBagConstraints);

        displayTabbedPane.addTab("Parsed", parsedPanel);

        add(displayTabbedPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    public static void main(String[] args) {
        final RequestPanel panel = new RequestPanel();
        javax.swing.JFrame top = new javax.swing.JFrame(panel.getName());
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        javax.swing.JButton button = new javax.swing.JButton("GET");
        top.getContentPane().add(panel);
        top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                try {
                    System.out.println(panel.getRequest());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        // top.setBounds(100,100,600,400);
        top.pack();
        top.setVisible(true);
        
        Request request = new Request();
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream("l2/conversations/1-request");
            request.read(fis);
        } catch (Exception e) {
            e.printStackTrace();
        }
        panel.setEditable(true);
        panel.setRequest(request);
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTabbedPane displayTabbedPane;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel messagePanelPlaceHolder;
    private javax.swing.JTextField methodTextField;
    private javax.swing.JPanel parsedPanel;
    private javax.swing.JTextField urlTextField;
    private javax.swing.JTextField versionTextField;
    // End of variables declaration//GEN-END:variables
    
}
