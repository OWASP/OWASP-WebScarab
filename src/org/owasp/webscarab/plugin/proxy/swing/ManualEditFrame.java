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

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.ui.swing.RequestPanel;
import org.owasp.webscarab.ui.swing.ResponsePanel;

import javax.swing.SwingUtilities;
import java.lang.Runnable;

import java.awt.Dimension;
import java.awt.Point;

/**
 *
 * @author  rdawes
 */
public class ManualEditFrame extends javax.swing.JFrame {
    
    private static Point _location = null;
    private static Dimension _size = new Dimension(600, 500);
    private static boolean _cancelAll = false;
    private static Object _lock = new Object();
    
    private boolean _done = false;
    private Request _request = null;
    private RequestPanel _requestPanel = null;
    private Response _response = null;
    private ResponsePanel _responsePanel = null;
    
    /** Creates new form ConversationEditorFrame */
    public ManualEditFrame() {
        initComponents();
        java.awt.GridBagConstraints gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTH;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 0.2;
        _requestPanel = new RequestPanel();
        getContentPane().add(_requestPanel, gridBagConstraints);
        _responsePanel = new ResponsePanel();
        gridBagConstraints.gridy = 1;
        gridBagConstraints.weighty = 1;
        _responsePanel.setVisible(false);
        getContentPane().add(_responsePanel, gridBagConstraints);
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
                    if (_size != null) setSize(_size);
                    if (_location != null) setLocation(_location);
                    show();
                    toFront();
                    requestFocus();
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
                    _responsePanel.setVisible(true);
                    if (_size != null) setSize(_size);
                    if (_location != null) setLocation(_location);
                    show();
                    toFront();
                    requestFocus();
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
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        jPanel1 = new javax.swing.JPanel();
        cancelButton = new javax.swing.JButton();
        cancelAllButton = new javax.swing.JButton();
        acceptButton = new javax.swing.JButton();
        abortButton = new javax.swing.JButton();

        getContentPane().setLayout(new java.awt.GridBagLayout());

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

        cancelButton.setText("Cancel edits");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        jPanel1.add(cancelButton, new java.awt.GridBagConstraints());

        cancelAllButton.setText("Cancel all edits");
        cancelAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelAllButtonActionPerformed(evt);
            }
        });

        jPanel1.add(cancelAllButton, new java.awt.GridBagConstraints());

        acceptButton.setText("Accept edits");
        acceptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                acceptButtonActionPerformed(evt);
            }
        });

        jPanel1.add(acceptButton, new java.awt.GridBagConstraints());

        abortButton.setText("Abort request");
        abortButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                abortButtonActionPerformed(evt);
            }
        });

        jPanel1.add(abortButton, new java.awt.GridBagConstraints());

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.SOUTH;
        gridBagConstraints.weightx = 1.0;
        getContentPane().add(jPanel1, gridBagConstraints);

        pack();
    }//GEN-END:initComponents
    
    private void cancelAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelAllButtonActionPerformed
        _cancelAll = true;
        _done = true;
        synchronized(_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_cancelAllButtonActionPerformed
    
    private void formComponentResized(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentResized
        if (isVisible()) _size = getSize();
    }//GEN-LAST:event_formComponentResized
    
    private void formComponentMoved(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentMoved
        if (isVisible()) _location = getLocation();
    }//GEN-LAST:event_formComponentMoved
    
    private void abortButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_abortButtonActionPerformed
        _done = true;
        _request = null;
        _response = null;
        synchronized (_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_abortButtonActionPerformed
    
    private void acceptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_acceptButtonActionPerformed
        if (_response != null) {
            _response = _responsePanel.getResponse();
        } else if (_request != null) {
            _request = _requestPanel.getRequest();
        }
        _done = true;
        synchronized (_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_acceptButtonActionPerformed
    
    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        _done = true;
        synchronized (_lock) {
            _lock.notifyAll();
        }
    }//GEN-LAST:event_cancelButtonActionPerformed
    
    /** Exit the Application */
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
    private javax.swing.JPanel jPanel1;
    // End of variables declaration//GEN-END:variables
    
}
