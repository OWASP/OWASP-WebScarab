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
 * SearchDialog.java
 *
 * Created on November 5, 2003, 11:14 PM
 */

package org.owasp.webscarab.ui.swing.editors;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowFocusListener;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JComponent;
import javax.swing.text.JTextComponent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.KeyStroke;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/**
 *
 * @author  rdawes
 */
public class SearchDialog extends javax.swing.JDialog {
    
    private JTextComponent _textComponent = null;
    
    /** Creates new form SearchDialog */
    public SearchDialog(java.awt.Frame parent, JTextComponent textComponent) {
        super(parent);
        if (textComponent == null) {
            throw new NullPointerException("Can't search a null text component!");
        }
        _textComponent = textComponent;
        initComponents();
        if (!_textComponent.isEditable()) {
            replaceButton.setVisible(false);
            replaceTextField.setVisible(false);
            replaceLabel.setVisible(false);
            pack();
        }
        String selection = _textComponent.getSelectedText();
        if (selection != null) {
            findTextField.setText(selection);
        }
        addWindowListener(new WindowAdapter() {
            public void windowActivated(WindowEvent evt) {
                findTextField.requestFocus();
            }
        });
        KeyStroke escapeKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false);
        Action escapeAction = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                setVisible( false );
            }
        };
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escapeKeyStroke, "ESCAPE");
        getRootPane().getActionMap().put("ESCAPE", escapeAction);
        getRootPane().setDefaultButton(searchButton);
    }
    
    public void doSearch() {
        if (_textComponent == null) {
            System.err.println("Uninitialised textComponent");
            return;
        }
        String searchText = findTextField.getText();
        if (searchText.length() > 0) {
            int caret = _textComponent.getSelectionStart();
            int position = _textComponent.getText().indexOf(searchText, caret+1);
            if (position == -1 && caret > 0) {
                position = _textComponent.getText().indexOf(searchText);
            }
            if (position > -1) {
                try {
                    _textComponent.setCaretPosition(position);
                    _textComponent.moveCaretPosition(position + searchText.length());
                } catch (IllegalArgumentException iae) {
                    System.err.println("error showing search results : " + iae);
                }
            } else {
                System.err.println("'" + searchText + "' not found!");
                _textComponent.setCaretPosition(caret);
            }
        }
    }
    
    public void doReplace() {
        if (_textComponent == null) {
            System.err.println("Uninitialised textComponent");
            return;
        }
        String searchText = findTextField.getText();
        String replaceText = replaceTextField.getText();
        if (searchText.length() > 0) {
            String text = _textComponent.getText();
            int caret = _textComponent.getSelectionStart();
            int position = _textComponent.getText().indexOf(searchText, caret);
            if (position == -1 && caret > 0) {
                position = _textComponent.getText().indexOf(searchText);
            }
            if (position < 0) {
                System.err.println("Search text not found");
                return;
            }
            text = text.substring(0,position) + replaceText + text.substring(position+searchText.length());
            _textComponent.setText(text);
            _textComponent.setCaretPosition(position);
            _textComponent.moveCaretPosition(position + replaceText.length());
        }
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        java.awt.GridBagConstraints gridBagConstraints;

        findLabel = new javax.swing.JLabel();
        findTextField = new javax.swing.JTextField();
        replaceLabel = new javax.swing.JLabel();
        replaceTextField = new javax.swing.JTextField();
        buttonPanel = new javax.swing.JPanel();
        searchButton = new javax.swing.JButton();
        replaceButton = new javax.swing.JButton();
        closeButton = new javax.swing.JButton();

        getContentPane().setLayout(new java.awt.GridBagLayout());

        setTitle("Find");
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                closeDialog(evt);
            }
        });

        findLabel.setText("Find ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        getContentPane().add(findLabel, gridBagConstraints);

        findTextField.setColumns(40);
        findTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                findTextFieldActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        getContentPane().add(findTextField, gridBagConstraints);

        replaceLabel.setText("Replace");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        getContentPane().add(replaceLabel, gridBagConstraints);

        replaceTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                replaceTextFieldActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        getContentPane().add(replaceTextField, gridBagConstraints);

        buttonPanel.setLayout(new java.awt.GridBagLayout());

        searchButton.setText("Search");
        searchButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                searchButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.weightx = 1.0;
        buttonPanel.add(searchButton, gridBagConstraints);

        replaceButton.setText("Replace");
        replaceButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                replaceButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        buttonPanel.add(replaceButton, gridBagConstraints);

        closeButton.setText("Close");
        closeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.weightx = 1.0;
        buttonPanel.add(closeButton, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        getContentPane().add(buttonPanel, gridBagConstraints);

        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        setBounds((screenSize.width-400)/2, (screenSize.height-120)/2, 400, 120);
    }
    // </editor-fold>//GEN-END:initComponents
    
    private void replaceTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_replaceTextFieldActionPerformed
        doReplace();
    }//GEN-LAST:event_replaceTextFieldActionPerformed
    
    private void findTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_findTextFieldActionPerformed
        doSearch();
    }//GEN-LAST:event_findTextFieldActionPerformed
    
    private void replaceButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_replaceButtonActionPerformed
        doReplace();
    }//GEN-LAST:event_replaceButtonActionPerformed
    
    private void searchButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchButtonActionPerformed
        doSearch();
    }//GEN-LAST:event_searchButtonActionPerformed
    
    private void closeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_closeButtonActionPerformed
        setVisible(false);
    }//GEN-LAST:event_closeButtonActionPerformed
    
    /** Closes the dialog */
    private void closeDialog(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_closeDialog
        setVisible(false);
    }//GEN-LAST:event_closeDialog
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        JTextComponent text = new javax.swing.JTextArea();
        text.setEditable(true);
        new SearchDialog(new javax.swing.JFrame(), text).setVisible(true);
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel buttonPanel;
    private javax.swing.JButton closeButton;
    private javax.swing.JLabel findLabel;
    private javax.swing.JTextField findTextField;
    private javax.swing.JButton replaceButton;
    private javax.swing.JLabel replaceLabel;
    private javax.swing.JTextField replaceTextField;
    private javax.swing.JButton searchButton;
    // End of variables declaration//GEN-END:variables
    
}
