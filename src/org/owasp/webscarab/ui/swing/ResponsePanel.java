/*
 * ResponsePanel.java
 *
 * Created on 02 June 2003, 03:09
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.ImageIcon;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;

import java.io.ByteArrayInputStream;

import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public class ResponsePanel extends javax.swing.JPanel {
    
    boolean[] validPanel;
    
    boolean editable = false;
    boolean error = false;
    Response response = null;
    
    /** Creates new form ResponsePanel */
    public ResponsePanel() {
        this(null);
    }
    
    public ResponsePanel(Response response) {
        this(response,false);
    }
    
    public ResponsePanel(Response response, boolean editable) {
        initComponents();
        setEditable(editable);
        setResponse(response);
        displayTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                int currentPanel = displayTabbedPane.getSelectedIndex();
                if (currentPanel == 0) {
                    updateResponse(1);
                } else if (currentPanel == 1) {
                    updateResponse(0);
                }
                updateFields(currentPanel);
            }
        });
    }
    
    public void setEditable(boolean editable) {
        this.editable = editable;
        if (editable) {
            rawTextArea.setEditable(true);
            rawTextArea.setBackground(new java.awt.Color(255, 255, 255));
        } else {
            rawTextArea.setEditable(false);
            rawTextArea.setBackground(new java.awt.Color(204, 204, 204));
        }
    }
    
    public void setResponse(Response response) {
        if (response!= null) {
            this.response = new Response(response);
        } else {
            this.response = null;
        }
        validPanel = new boolean[] {false, false};
        updateFields(displayTabbedPane.getSelectedIndex());
    }
    
    public Response getResponse() {
        int panel = displayTabbedPane.getSelectedIndex();
        updateResponse(panel);
        return this.response;
    }
    
    private void updateFields(int panel) {
        if (validPanel[panel]) return;
        if (response != null) {
            if (panel == 0) {
                rawTextArea.setText(response.toString("\n"));
                rawTextArea.setCaretPosition(0);
            } else if (panel == 1) {
                statusTextField.setText(response.getStatus());
                messageTextField.setText(response.getMessage());
                String ct = response.getHeader("Content-Type");
                if (ct == null) {
                    htmlEditorPane.setVisible(false);
                    imageLabel.setText("No Content-Type header");
                    imageLabel.setIcon(null);
                    imageLabel.setVisible(true);
                } else {
                    System.err.println("Content Type is " + ct);
                    if (ct.matches("text/.*")) {
                        imageLabel.setVisible(false);
                        htmlEditorPane.setContentType(ct);
                        htmlEditorPane.putClientProperty("IgnoreCharsetDirective", Boolean.TRUE);
                        htmlEditorPane.getDocument().putProperty("IgnoreCharsetDirective", Boolean.TRUE);
                        htmlEditorPane.setText(new String(response.getContent()));
                        htmlEditorPane.setCaretPosition(0);
                        htmlEditorPane.setVisible(true);
                    } else if (ct.matches("image/.*")) {
                        htmlEditorPane.setVisible(false);
                        ImageIcon ii = new ImageIcon(response.getContent());
                        imageLabel.setIcon(ii);
                        imageLabel.setText("");
                        imageLabel.setVisible(true);
                    } else {
                        htmlEditorPane.setVisible(false);
                        imageLabel.setText("Unknown Content-Type " + ct);
                        imageLabel.setIcon(null);
                        imageLabel.setVisible(true);
                    }
                }
            }
        } else {
            if (panel == 0) {
                rawTextArea.setText("");
            } else if (panel == 1) {
                statusTextField.setText("");
                messageTextField.setText("");
                htmlEditorPane.setText("");
                imageLabel.setIcon(null);
                imageLabel.setText("");
            }
        }
        validPanel[panel] = true;
    }
    
    private void updateResponse(int pane) {
        if (error) return;
        if (editable && pane == 0) {
            // we must parse the rawTextArea
            try {
                if (response == null) response = new Response();
                response.read(new ByteArrayInputStream(rawTextArea.getText().getBytes()));
                String cl = response.getHeader("Content-Length");
                if (cl != null) {
                    byte[] content = response.getContent();
                    if (content == null) {
                        response.setHeader("Content-Length","0");
                    } else {
                        response.setHeader("Content-Length", Integer.toString(content.length));
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                response = null;
                error = true;
                displayTabbedPane.setSelectedIndex(0);
                return;
            }
            validPanel[pane] = false;
        } else if (editable && pane == 1) {
            // The image and HTML is not editable
        }
        error = false;
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        displayTabbedPane = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        rawTextArea = new javax.swing.JTextArea();
        jPanel2 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        statusTextField = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        messageTextField = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        jPanel3 = new javax.swing.JPanel();
        imageLabel = new javax.swing.JLabel();
        htmlEditorPane = new javax.swing.JEditorPane();

        setLayout(new java.awt.BorderLayout());

        jPanel1.setLayout(new java.awt.GridBagLayout());

        rawTextArea.setBackground(new java.awt.Color(204, 204, 204));
        rawTextArea.setEditable(false);
        jScrollPane2.setViewportView(rawTextArea);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel1.add(jScrollPane2, gridBagConstraints);

        displayTabbedPane.addTab("Raw", jPanel1);

        jPanel2.setLayout(new java.awt.GridBagLayout());

        jLabel3.setLabelFor(statusTextField);
        jLabel3.setText("Status");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(jLabel3, gridBagConstraints);

        statusTextField.setEditable(false);
        statusTextField.setText("200");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(statusTextField, gridBagConstraints);

        jLabel4.setLabelFor(messageTextField);
        jLabel4.setText("Message");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(jLabel4, gridBagConstraints);

        messageTextField.setEditable(false);
        messageTextField.setText("Ok");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(messageTextField, gridBagConstraints);

        jScrollPane1.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        jPanel3.setLayout(new java.awt.GridBagLayout());

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel3.add(imageLabel, gridBagConstraints);

        htmlEditorPane.setBackground(new java.awt.Color(204, 204, 204));
        htmlEditorPane.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel3.add(htmlEditorPane, gridBagConstraints);

        jScrollPane1.setViewportView(jPanel3);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.gridheight = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        jPanel2.add(jScrollPane1, gridBagConstraints);

        displayTabbedPane.addTab("MIME", jPanel2);

        add(displayTabbedPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    public static void main(String[] args) {
        javax.swing.JFrame top = new javax.swing.JFrame("Response Panel");
        ResponsePanel rp = new ResponsePanel();
        top.getContentPane().add(rp);
        top.setBounds(100,100,600,400);
        Response response = new Response();
        response.setVersion("HTTP/1.0");
        response.setStatus("200");
        response.setMessage("ok");
        response.setHeader("Set-Cookie","name=value; path=/");
        // h.set("Content-Type","text/html");
        response.setHeader("Content-Type","image/gif");
        // response.setContent("<HTML><HEAD>title</HEAD><BODY><B>BOLD</B><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P><P></P> <I>Italic</I><P></P></BODY></HTML>".getBytes());
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream("/var/www/icons/apache_pb2_ani.gif");
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[2048];
            int read;
            while ((read=fis.read(buf)) > -1) {
                baos.write(buf,0,read);
            }
            response.setContent(baos.toByteArray());
            rp.setResponse(response);
            top.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JTextArea rawTextArea;
    private javax.swing.JLabel imageLabel;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JEditorPane htmlEditorPane;
    private javax.swing.JTextField statusTextField;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JTabbedPane displayTabbedPane;
    private javax.swing.JTextField messageTextField;
    // End of variables declaration//GEN-END:variables
    
}
