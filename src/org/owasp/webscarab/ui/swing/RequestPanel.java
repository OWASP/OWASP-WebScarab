/*
 * RequestPanel.java
 *
 * Created on 02 June 2003, 03:09
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.ImageIcon;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;

import java.io.ByteArrayInputStream;
import java.net.URL;

import org.owasp.webscarab.model.Request;

import org.owasp.webscarab.ui.swing.editors.BeanShellPanel;
import org.owasp.webscarab.ui.swing.editors.TextPanel;

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
    private BeanShellPanel _beanShellPanel;
    private TextPanel _textPanel;
    
    /** Creates new form RequestPanel */
    public RequestPanel() {
        initComponents();
        
        displayTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                updateRequest(_selected);
                _selected = displayTabbedPane.getSelectedIndex();
                if (_selected >= 0) {
                    updatePanel(_selected);
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
        
        _beanShellPanel = new BeanShellPanel();
        displayTabbedPane.add("Bean Script", _beanShellPanel);
        _textPanel = new TextPanel();
        displayTabbedPane.add("Raw", _textPanel);
        
        _upToDate = new boolean[displayTabbedPane.getTabCount()];
        invalidatePanels();
        
        setEditable(_editable);
    }
    
    private void invalidatePanels() {
        for (int i=0; i<_upToDate.length; i++) {
            _upToDate[i] = false;
        }
    }
    
    private void updateRequest(int panel) {
        if (! _editable || panel < 0) {
            return;
        }
        if (panel == 0) {// parsed text
            if (_messagePanel.isModified()) {
                _request = (Request) _messagePanel.getMessage();
                _modified = true;
                invalidatePanels();
            }
            if (_request == null) {
                _request = new Request();
            }
            // if _modified
            _request.setMethod(methodTextField.getText());
            try {
                _request.setURL(urlTextField.getText());
            } catch (Exception e) {
                URL url = _request.getURL();
                if (url != null) {
                    urlTextField.setText(url.toString());
                } else {
                    urlTextField.setText("");
                }
            }
            _request.setVersion(versionTextField.getText());
        } else if (panel == 1) {// bean shell
            _modified = true;
            invalidatePanels();
            _request = _beanShellPanel.getRequest();
        } else if (panel == 2) { // raw text
            if (_textPanel.isModified()) {
                try {
                    Request r = new Request();
                    ByteArrayInputStream bais = new ByteArrayInputStream(_textPanel.getBytes());
                    r.read(bais);
                    r.getContent();
                    String cl = _request.getHeader("Content-Length");
                    if (cl != null) {
                        byte[] content = _request.getContent(); // read the content
                        if (content == null) {
                            _request.setHeader("Content-Length","0"); // update the header
                        } else {
                            _request.setHeader("Content-Length", Integer.toString(content.length));
                        }
                    }
                    _request = r;
                } catch (Exception e) {
                    System.err.println("Error parsing the rawTextArea, abandoning changes : " + e);
                }
                _modified = true;
                invalidatePanels();
            }
        }
        _upToDate[panel] = true;
    }
    
    private void updatePanel(int panel) {
        if (!_upToDate[panel]) {
            if (panel == 0) {// parsed text
                _messagePanel.setMessage(_request);
                if (_request != null) {
                    methodTextField.setText(_request.getMethod());
                    urlTextField.setText(_request.getURL().toString());
                    versionTextField.setText(_request.getVersion());
                } else {
                    methodTextField.setText("");
                    urlTextField.setText("");
                    versionTextField.setText("");
                }
            } else if (panel == 1) {// bean shell
                _beanShellPanel.setRequest(_request);
            } else if (panel == 2) { // raw text
                if (_request != null) {
                    _textPanel.setBytes(_request.toString("\n").getBytes());
                } else {
                    _textPanel.setBytes(new byte[0]);
                }
            }
            _upToDate[panel] = true;
        }
    }

    public void setEditable(boolean editable) {
        _editable = editable;
        _messagePanel.setEditable(editable);
        _beanShellPanel.setEditable(editable);
        _textPanel.setEditable(editable);
        
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
    
    public void setRequest(Request request) {
        _modified = false;
        if (request != null) {
            _request = new Request(request);
        } else {
            _request = null;
        }
        invalidatePanels();
        updatePanel(displayTabbedPane.getSelectedIndex());
    }
    
    public Request getRequest() {
        if (_editable) {
            int panel = displayTabbedPane.getSelectedIndex();
            updateRequest(panel);
        }
        return _request;
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
        javax.swing.JFrame top = new javax.swing.JFrame("Request Panel");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        javax.swing.JButton button = new javax.swing.JButton("GET");
        final RequestPanel rp = new RequestPanel();
        top.getContentPane().add(rp);
        top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                System.out.println(rp.getRequest());
            }
        });
        top.setBounds(100,100,600,400);
        Request request = new Request();
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream("/home/rdawes/santam/webscarab/conversations/48-request");
            request.read(fis);
        } catch (Exception e) {
            e.printStackTrace();
        }
        rp.setEditable(true);
        rp.setRequest(request);
        top.show();
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
