/*
 * ResponsePanel.java
 *
 * Created on 02 June 2003, 03:09
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.ImageIcon;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.SwingUtilities;

import java.io.ByteArrayInputStream;

import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.ui.swing.editors.BeanShellPanel;
import org.owasp.webscarab.ui.swing.editors.TextPanel;

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
    private BeanShellPanel _beanShellPanel;
    private TextPanel _textPanel;
    
    /** Creates new form ResponsePanel */
    public ResponsePanel() {
        initComponents();
        
        displayTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                updateResponse(_selected);
                _selected = displayTabbedPane.getSelectedIndex();
                if (_selected >= 0) {
                    updatePanel(_selected);
                }
            }
        });

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
        
        _beanShellPanel = new BeanShellPanel();
        displayTabbedPane.add("Bean Script", _beanShellPanel);
        _textPanel = new TextPanel();
        displayTabbedPane.add("Raw", _textPanel);
        
        _upToDate = new boolean[displayTabbedPane.getTabCount()];
        invalidatePanels();
        
        updateComponents(_editable);
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
        if (panel == 0) {// parsed text
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
        } else if (panel == 1) {// bean shell
            _modified = true; // we have to assume that the bean shell has modified the response
            invalidatePanels();
            // BeanShell modifies our copy of _response directly, no need to fetch it
            // _response = _beanShellPanel.getResponse();
        } else if (panel == 2) { // raw text
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
    
    private void updatePanel(int panel) {
        if (!_upToDate[panel]) {
            if (panel == 0) {// parsed text
                _messagePanel.setMessage(_response, _editable);
                if (_response != null) {
                    statusTextField.setText(_response.getStatus());
                    messageTextField.setText(_response.getMessage());
                    versionTextField.setText(_response.getVersion());
                } else {
                    statusTextField.setText("");
                    messageTextField.setText("");
                    versionTextField.setText("");
                }
            } else if (panel == 1) {// bean shell
                try {
                    _beanShellPanel.setVariable("response", _response);
                } catch (bsh.EvalError ee) {
                    System.err.println("Exception setting the response in the BeanShell : " + ee);
                }
            } else if (panel == 2) { // raw text
                if (_response != null) {
                    _textPanel.setBytes(_response.toString("\n").getBytes());
                } else {
                    _textPanel.setBytes(new byte[0]);
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
    
    public void setResponse(Response response, boolean editable) {
        _editable = editable;
        // _beanShellPanel.setEditable(editable); // it is editable regardless ;-)
        _textPanel.setEditable(editable);
        
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
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        parsedPanel.add(jLabel3, gridBagConstraints);

        statusTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        parsedPanel.add(statusTextField, gridBagConstraints);

        jLabel4.setLabelFor(messageTextField);
        jLabel4.setText("Message");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        parsedPanel.add(jLabel4, gridBagConstraints);

        messageTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
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
        javax.swing.JFrame top = new javax.swing.JFrame("Response Panel");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        javax.swing.JButton button = new javax.swing.JButton("GET");
        final ResponsePanel rp = new ResponsePanel();
        top.getContentPane().add(rp);
        top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                System.out.println(rp.getResponse());
            }
        });
        top.setBounds(100,100,600,400);
        Response response = new Response();
        try {
            String resp = "l2/conversations/1-response";
            if (args.length == 1) {
                resp = args[0];
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(resp);
            response.read(fis);
        } catch (Exception e) {
            e.printStackTrace();
        }
        rp.setResponse(response, false);
        top.show();
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JTextField versionTextField;
    private javax.swing.JPanel messagePanelPlaceHolder;
    private javax.swing.JPanel parsedPanel;
    private javax.swing.JTextField statusTextField;
    private javax.swing.JTabbedPane displayTabbedPane;
    private javax.swing.JTextField messageTextField;
    private javax.swing.JLabel jLabel5;
    // End of variables declaration//GEN-END:variables
    
}
