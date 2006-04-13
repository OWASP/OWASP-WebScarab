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
 * $Id: ManualEditPanel.java,v 1.8 2005/05/19 15:20:56 rogan Exp $
 * ProxyUI.java
 *
 * Created on February 17, 2003, 9:05 PM
 */

package org.owasp.webscarab.plugin.proxy.swing;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.proxy.ManualEdit;
import org.owasp.webscarab.plugin.proxy.ManualEditUI;

import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;

import javax.swing.ButtonModel;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ListModel;
import javax.swing.JPanel;

/**
 *
 * @author  rdawes
 */
public class ManualEditPanel extends javax.swing.JPanel implements ProxyPluginUI, ManualEditUI {
    
    private ManualEdit _manualEdit;
    private ButtonModel _requestButtonModel, _responseButtonModel;
    
    /** Creates new form ManualEditPanel */
    public ManualEditPanel(ManualEdit manualEdit) {
        _manualEdit = manualEdit;
        initComponents();
        _requestButtonModel = interceptRequestCheckBox.getModel();
        _requestButtonModel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                boolean enabled = interceptRequestCheckBox.isSelected();
                interceptIncludeRegexTextField.setEnabled(isEnabled() && enabled);
                interceptExcludeRegexTextField.setEnabled(isEnabled() && enabled);
                interceptMethodList.setEnabled(isEnabled() && enabled);
                _manualEdit.setInterceptRequest(enabled);
            }
        });
        _responseButtonModel = interceptResponseCheckBox.getModel();
        _responseButtonModel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                boolean enabled = interceptResponseCheckBox.isSelected();
                interceptResponseTextField.setEnabled(isEnabled() && enabled);
                _manualEdit.setInterceptResponse(enabled);
            }
        });
        configure();
        interceptMethodList.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                interceptMethodListValueChanged(evt);
            }
        });
        _manualEdit.setUI(this);
    }
    
    public String getPluginName() {
        return new String("Manual Edit");
    }
    
    public void configure() {
        boolean enabled = _manualEdit.getInterceptRequest();
        interceptRequestCheckBox.setSelected(enabled);
        
        sensitiveCheckBox.setSelected(_manualEdit.isCaseSensitive());
        
        interceptIncludeRegexTextField.setEnabled(isEnabled() && enabled);
        interceptIncludeRegexTextField.setText(_manualEdit.getIncludeRegex());
        
        interceptExcludeRegexTextField.setEnabled(isEnabled() && enabled);
        interceptExcludeRegexTextField.setText(_manualEdit.getExcludeRegex());
        
        interceptMethodList.setEnabled(isEnabled() && enabled);
        String[] interceptMethods = _manualEdit.getInterceptMethods();
        interceptMethodList.setSelectedIndices(getIndices(interceptMethods,interceptMethodList.getModel()));
        
        enabled = _manualEdit.getInterceptResponse();
        interceptResponseTextField.setEnabled(isEnabled() && enabled);
        interceptResponseCheckBox.setSelected(_manualEdit.getInterceptResponse());
        interceptResponseTextField.setText(_manualEdit.getInterceptResponseRegex());
    }
    
    private int[] getIndices(String[] items, ListModel model) {
        int[] indices = new int[items.length];
        for (int i=0; i< items.length; i++) {
            boolean found = false;
            for (int j=0; j<model.getSize(); j++) {
                if (items[i].equals(model.getElementAt(j))) {
                    indices[i] = j;
                    found = true;
                }
            }
            if (!found) {
                indices[i] = -1;
                System.err.println("Did not find item["+i+"] == '" + items[i] + "' in the list model");
            }
        }
        return indices;
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        interceptrequestPanel = new javax.swing.JPanel();
        interceptRequestCheckBox = new javax.swing.JCheckBox();
        sensitiveCheckBox = new javax.swing.JCheckBox();
        interceptIncludeLabel = new javax.swing.JLabel();
        interceptIncludeRegexTextField = new javax.swing.JTextField();
        interceptExcludeLabel = new javax.swing.JLabel();
        interceptExcludeRegexTextField = new javax.swing.JTextField();
        jScrollPane3 = new javax.swing.JScrollPane();
        interceptMethodList = new javax.swing.JList();
        interceptResponsePanel = new javax.swing.JPanel();
        interceptResponseCheckBox = new javax.swing.JCheckBox();
        interceptResponseTextField = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();

        setLayout(new java.awt.GridBagLayout());

        interceptrequestPanel.setLayout(new java.awt.GridBagLayout());

        interceptRequestCheckBox.setText("Intercept requests : ");
        interceptRequestCheckBox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 0);
        interceptrequestPanel.add(interceptRequestCheckBox, gridBagConstraints);

        sensitiveCheckBox.setText("Case Sensitive Regular Expressions ?");
        sensitiveCheckBox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        sensitiveCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sensitiveCheckBoxActionPerformed(evt);
            }
        });

        interceptrequestPanel.add(sensitiveCheckBox, new java.awt.GridBagConstraints());

        interceptIncludeLabel.setText("Include Paths matching : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 0);
        interceptrequestPanel.add(interceptIncludeLabel, gridBagConstraints);

        interceptIncludeRegexTextField.setToolTipText("Use a regular expression to select which URLs to intercept. Leave blank to ignore.");
        interceptIncludeRegexTextField.setEnabled(false);
        interceptIncludeRegexTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                interceptIncludeRegexTextFieldActionPerformed(evt);
            }
        });
        interceptIncludeRegexTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                interceptIncludeRegexTextFieldFocusLost(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 5);
        interceptrequestPanel.add(interceptIncludeRegexTextField, gridBagConstraints);

        interceptExcludeLabel.setText("Exclude paths matching : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 0);
        interceptrequestPanel.add(interceptExcludeLabel, gridBagConstraints);

        interceptExcludeRegexTextField.setToolTipText("Use a regular expression to select which URLs not to intercept. Leave blank to ignore.");
        interceptExcludeRegexTextField.setEnabled(false);
        interceptExcludeRegexTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                interceptExcludeRegexTextFieldActionPerformed(evt);
            }
        });
        interceptExcludeRegexTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                interceptExcludeRegexTextFieldFocusLost(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 4;
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 5);
        interceptrequestPanel.add(interceptExcludeRegexTextField, gridBagConstraints);

        jScrollPane3.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        jScrollPane3.setViewportBorder(new javax.swing.border.TitledBorder("Methods"));
        jScrollPane3.setMinimumSize(new java.awt.Dimension(100, 120));
        jScrollPane3.setPreferredSize(new java.awt.Dimension(100, 120));
        jScrollPane3.setAutoscrolls(true);
        interceptMethodList.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "GET", "POST", "HEAD", "PUT", "DELETE", "TRACE", "PROPFIND", "OPTIONS" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        interceptMethodList.setToolTipText("Select which request methods to intercept");
        interceptMethodList.setVisibleRowCount(0);
        interceptMethodList.setEnabled(false);
        jScrollPane3.setViewportView(interceptMethodList);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridheight = 5;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 0.1;
        gridBagConstraints.weighty = 1.0;
        interceptrequestPanel.add(jScrollPane3, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(interceptrequestPanel, gridBagConstraints);

        interceptResponsePanel.setLayout(new java.awt.GridBagLayout());

        interceptResponseCheckBox.setText("Intercept responses : ");
        interceptResponseCheckBox.setToolTipText("");
        interceptResponseCheckBox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 0);
        interceptResponsePanel.add(interceptResponseCheckBox, gridBagConstraints);

        interceptResponseTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                interceptResponseTextFieldActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 5);
        interceptResponsePanel.add(interceptResponseTextField, gridBagConstraints);

        jLabel1.setText("Only MIME-Types matching :");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 5, 0, 0);
        interceptResponsePanel.add(jLabel1, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(interceptResponsePanel, gridBagConstraints);

    }//GEN-END:initComponents
    
    private void sensitiveCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sensitiveCheckBoxActionPerformed
        _manualEdit.setCaseSensitive(sensitiveCheckBox.isSelected());
    }//GEN-LAST:event_sensitiveCheckBoxActionPerformed
    
    private void interceptResponseTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_interceptResponseTextFieldActionPerformed
        _manualEdit.setInterceptResponseRegex(interceptResponseTextField.getText());
    }//GEN-LAST:event_interceptResponseTextFieldActionPerformed
    
    private void interceptExcludeRegexTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_interceptExcludeRegexTextFieldFocusLost
        _manualEdit.setExcludeRegex(interceptExcludeRegexTextField.getText());
    }//GEN-LAST:event_interceptExcludeRegexTextFieldFocusLost
    
    private void interceptExcludeRegexTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_interceptExcludeRegexTextFieldActionPerformed
        _manualEdit.setExcludeRegex(interceptExcludeRegexTextField.getText());
    }//GEN-LAST:event_interceptExcludeRegexTextFieldActionPerformed
    
    private void interceptIncludeRegexTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_interceptIncludeRegexTextFieldFocusLost
        _manualEdit.setIncludeRegex(interceptIncludeRegexTextField.getText());
    }//GEN-LAST:event_interceptIncludeRegexTextFieldFocusLost
    
    private void interceptIncludeRegexTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_interceptIncludeRegexTextFieldActionPerformed
        _manualEdit.setIncludeRegex(interceptIncludeRegexTextField.getText());
    }//GEN-LAST:event_interceptIncludeRegexTextFieldActionPerformed
            
    private void interceptMethodListValueChanged(ListSelectionEvent evt) {
        int[] indices = interceptMethodList.getSelectedIndices();
        String[] methods = new String[indices.length];
        ListModel lm = interceptMethodList.getModel();
        for (int i=0; i< indices.length; i++) {
            methods[i] = (String) lm.getElementAt(indices[i]);
        }
        _manualEdit.setInterceptMethods(methods);
    }
    
    public JPanel getPanel() {
        return this;
    }
    
    public Request editRequest(Request request) {
        ManualEditFrame mef = new ManualEditFrame();
        mef.setTitle("Edit Request");
        mef.setInterceptModels(interceptRequestCheckBox.getModel(), interceptResponseCheckBox.getModel());
        return mef.editRequest(request);
    }
    
    public Response editResponse(Request request, Response response) {
        ManualEditFrame mef = new ManualEditFrame();
        mef.setTitle("Edit Response");
        mef.setInterceptModels(interceptRequestCheckBox.getModel(), interceptResponseCheckBox.getModel());
        return mef.editResponse(request, response);
    }
    
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        interceptRequestCheckBox.setEnabled(enabled);
        interceptResponseCheckBox.setEnabled(enabled);
        interceptMethodList.setEnabled(enabled && interceptRequestCheckBox.isSelected());
        interceptIncludeRegexTextField.setEnabled(enabled && interceptRequestCheckBox.isSelected());
        interceptExcludeRegexTextField.setEnabled(enabled && interceptRequestCheckBox.isSelected());
        interceptResponseTextField.setEnabled(enabled && interceptResponseCheckBox.isSelected());
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel interceptExcludeLabel;
    private javax.swing.JTextField interceptExcludeRegexTextField;
    private javax.swing.JLabel interceptIncludeLabel;
    private javax.swing.JTextField interceptIncludeRegexTextField;
    private javax.swing.JList interceptMethodList;
    private javax.swing.JCheckBox interceptRequestCheckBox;
    private javax.swing.JCheckBox interceptResponseCheckBox;
    private javax.swing.JPanel interceptResponsePanel;
    private javax.swing.JTextField interceptResponseTextField;
    private javax.swing.JPanel interceptrequestPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JCheckBox sensitiveCheckBox;
    // End of variables declaration//GEN-END:variables
    
}
