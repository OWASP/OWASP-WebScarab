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
 * ConversationEditorFrame.java
 *
 * Created on June 5, 2003, 8:43 PM
 */

package org.owasp.webscarab.plugin.proxy.swing;

import java.net.MalformedURLException;
import javax.swing.JOptionPane;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.ui.swing.RequestPanel;
import org.owasp.webscarab.ui.swing.ResponsePanel;

import javax.swing.SwingUtilities;
import javax.swing.ButtonModel;
import java.lang.Runnable;

/**
 *
 * @author  rdawes
 */
public class ManualEditFrame extends javax.swing.JFrame {
    
    private static boolean _cancelAll = false;
    private static Object _lock = new Object();
    
    private boolean _done = false;
    private Request _request = null;
    private RequestPanel _requestPanel = null;
    private Response _response = null;
    private ResponsePanel _responsePanel = null;
    
    /** Creates new form ManualEditFrame */
    public ManualEditFrame() {
        initComponents();
        setPreferredSize();
        _requestPanel = new RequestPanel();
        contentSplitPane.setTopComponent(_requestPanel);
        _responsePanel = new ResponsePanel();
        contentSplitPane.setBottomComponent(_responsePanel);
        getRootPane().setDefaultButton(acceptButton);
    }
    
    public void setInterceptModels(ButtonModel interceptRequest, ButtonModel interceptResponse) {
        interceptRequestCheckBox.setModel(interceptRequest);
        interceptRequestCheckBox.setEnabled(true);
        interceptRequestCheckBox.setVisible(true);
        interceptResponseCheckBox.setModel(interceptResponse);
        interceptResponseCheckBox.setEnabled(true);
        interceptResponseCheckBox.setVisible(true);
    }
    
    public Request editRequest(Request request) {
        synchronized (_lock) {
            _cancelAll = false;
            _done = false;
            _request = request;
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    _requestPanel.setEditable(true);
                    _requestPanel.setRequest(_request);
                    _responsePanel.setEditable(false);
                    _responsePanel.setResponse(null);
                    setVisible(true);
                    toFront();
                    requestFocus();
                    contentSplitPane.setDividerLocation(1.0);
                }
            });
            do {
                try {
                    _lock.wait();
                } catch (InterruptedException ie) {
                    System.out.println("Wait interrupted");
                }
            } while (! _cancelAll && ! _done);
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    setVisible(false);
                    dispose();
                }
            });
            return _request;
        }
    }
    
    public Response editResponse(final Request request, final Response response) {
        synchronized (_lock) {
            _cancelAll = false;
            _done = false;
            _response = response;
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    _requestPanel.setEditable(false);
                    _requestPanel.setRequest(request);
                    _responsePanel.setEditable(true);
                    _responsePanel.setResponse(_response);
                    setVisible(true);
                    toFront();
                    requestFocus();
                    contentSplitPane.setDividerLocation(0.3);
                }
            });
            do {
                try {
                    _lock.wait();
                } catch (InterruptedException ie) {
                    System.out.println("Wait interrupted");
                }
            } while (! _cancelAll && ! _done);
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    setVisible(false);
                    dispose();
                }
            });
            return _response;
        }
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        jPanel1 = new javax.swing.JPanel();
        acceptButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        abortButton = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        cancelAllButton = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        interceptRequestCheckBox = new javax.swing.JCheckBox();
        interceptResponseCheckBox = new javax.swing.JCheckBox();
        contentSplitPane = new javax.swing.JSplitPane();

        setTitle("Intercept");
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentMoved(java.awt.event.ComponentEvent evt) {
                formComponentMoved(evt);
            }
            public void componentResized(java.awt.event.ComponentEvent evt) {
                formComponentResized(evt);
            }
        });
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                exitForm(evt);
            }
        });

        jPanel1.setLayout(new java.awt.GridBagLayout());

        acceptButton.setText("Accept changes");
        acceptButton.setToolTipText("Accepts any changes made to this conversation");
        acceptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                acceptButtonActionPerformed(evt);
            }
        });

        jPanel1.add(acceptButton, new java.awt.GridBagConstraints());

        cancelButton.setText("Cancel changes");
        cancelButton.setToolTipText("Cancels any changes made to this conversation");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        jPanel1.add(cancelButton, new java.awt.GridBagConstraints());

        abortButton.setText("Abort request");
        abortButton.setToolTipText("Prevents this request from being sent to the server. Returns an error to the browser");
        abortButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                abortButtonActionPerformed(evt);
            }
        });

        jPanel1.add(abortButton, new java.awt.GridBagConstraints());

        jSeparator1.setOrientation(javax.swing.SwingConstants.VERTICAL);
        jSeparator1.setMinimumSize(new java.awt.Dimension(20, 0));
        jSeparator1.setPreferredSize(new java.awt.Dimension(20, 0));
        jPanel1.add(jSeparator1, new java.awt.GridBagConstraints());

        cancelAllButton.setText("Cancel ALL intercepts");
        cancelAllButton.setToolTipText("Cancels any pending changes, and allows intercepted conversations to proceed");
        cancelAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelAllButtonActionPerformed(evt);
            }
        });

        jPanel1.add(cancelAllButton, new java.awt.GridBagConstraints());

        getContentPane().add(jPanel1, java.awt.BorderLayout.SOUTH);

        interceptRequestCheckBox.setText("Intercept requests : ");
        interceptRequestCheckBox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        interceptRequestCheckBox.setEnabled(false);
        jPanel2.add(interceptRequestCheckBox);

        interceptResponseCheckBox.setText("Intercept responses : ");
        interceptResponseCheckBox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        interceptResponseCheckBox.setEnabled(false);
        jPanel2.add(interceptResponseCheckBox);

        getContentPane().add(jPanel2, java.awt.BorderLayout.NORTH);

        contentSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        contentSplitPane.setResizeWeight(0.5);
        contentSplitPane.setOneTouchExpandable(true);
        getContentPane().add(contentSplitPane, java.awt.BorderLayout.CENTER);

        pack();
    }
    // </editor-fold>//GEN-END:initComponents
    
    private void cancelAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelAllButtonActionPerformed
        _cancelAll = true;
        _done = true;
        synchronized(_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_cancelAllButtonActionPerformed
    
    private void formComponentResized(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentResized
        if (!isShowing()) return;
        Preferences.getPreferences().setProperty("ManualEditFrame.size.x",Integer.toString(getWidth()));
        Preferences.getPreferences().setProperty("ManualEditFrame.size.y",Integer.toString(getHeight()));
    }//GEN-LAST:event_formComponentResized
    
    private void formComponentMoved(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentMoved
        if (!isShowing()) return;
        Preferences.getPreferences().setProperty("ManualEditFrame.position.x",Integer.toString(getX()));
        Preferences.getPreferences().setProperty("ManualEditFrame.position.y",Integer.toString(getY()));
    }//GEN-LAST:event_formComponentMoved
    
    private void setPreferredSize() {
        try {
            int xpos = Integer.parseInt(Preferences.getPreference("ManualEditFrame.position.x").trim());
            int ypos = Integer.parseInt(Preferences.getPreference("ManualEditFrame.position.y").trim());
            int width = Integer.parseInt(Preferences.getPreference("ManualEditFrame.size.x").trim());
            int height = Integer.parseInt(Preferences.getPreference("ManualEditFrame.size.y").trim());
            setBounds(xpos,ypos,width,height);
        } catch (NumberFormatException nfe) {
            setSize(800,600);
        } catch (NullPointerException npe) {
            setSize(800,600);
        }
    }
    
    private void abortButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_abortButtonActionPerformed
        _done = true;
        _request = null;
        _response = null;
        synchronized (_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_abortButtonActionPerformed
    
    private void acceptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_acceptButtonActionPerformed
        try {
            if (_response != null) {
                _response = _responsePanel.getResponse();
            } else if (_request != null) {
                _request = _requestPanel.getRequest();
            }
            _done = true;
            synchronized (_lock) {
                _lock.notifyAll();
            }
        } catch (MalformedURLException mue) {
            JOptionPane.showMessageDialog(this, new String[] {"The URL requested is malformed", mue.getMessage()}, "Malformed URL", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_acceptButtonActionPerformed
    
    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        _done = true;
        synchronized (_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_cancelButtonActionPerformed
    
    private void exitForm(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_exitForm
        _done = true;
        synchronized (_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_exitForm
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton abortButton;
    private javax.swing.JButton acceptButton;
    private javax.swing.JButton cancelAllButton;
    private javax.swing.JButton cancelButton;
    private javax.swing.JSplitPane contentSplitPane;
    private javax.swing.JCheckBox interceptRequestCheckBox;
    private javax.swing.JCheckBox interceptResponseCheckBox;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables
    
}
