/***********************************************************************
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 FedICT
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
 */
package org.owasp.webscarab.plugin.openid.swing;

import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.Action;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.plugin.openid.OpenId;
import org.owasp.webscarab.plugin.openid.OpenIdModel;
import org.owasp.webscarab.plugin.openid.PAPEResponse;
import org.owasp.webscarab.ui.swing.ColumnWidthTracker;
import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.ui.swing.ShowConversationAction;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.TableSorter;

/**
 *
 * @author Frank Cornelis
 */
public class OpenIdPanel extends JPanel implements SwingPluginUI {
    
    private final OpenId openId;
    private final OpenIdModel openIdModel;
    private final ShowConversationAction showConversationAction;
    private final ParametersTableModel parametersTableModel;
    private final AXFetchRequestTableModel axFetchRequestTableModel;
    private final AXFetchResponseTableModel axFetchResponseTableModel;
    
    public OpenIdPanel(OpenId openId) {
        this.openId = openId;
        this.openIdModel = openId.getModel();
        initComponents();
        
        this.showConversationAction = new ShowConversationAction(this.openIdModel.getOpenIDConversationModel());
        this.openIdPopupMenu.add(new JMenuItem(this.showConversationAction));
        
        ConversationTableModel openIdTableModel = new ConversationTableModel(
                this.openIdModel.getOpenIDConversationModel());
        openIdTableModel.addColumn(new ColumnDataModel() {
            
            public String getColumnName() {
                return "OpenID Type";
            }
            
            public Object getValue(Object key) {
                ConversationID conversationId = (ConversationID) key;
                return OpenIdPanel.this.openIdModel.getReadableOpenIDMessageType(
                        conversationId);
            }
            
            public Class getColumnClass() {
                return String.class;
            }
        });
        ColumnWidthTracker.getTracker("OpenIDTable").addTable(this.openIdTable);
        TableSorter sorterOpenIdTableModel = new TableSorter(openIdTableModel);
        this.openIdTable.setModel(sorterOpenIdTableModel);
        addTableListeners();
        
        this.parametersTableModel = new ParametersTableModel();
        this.parametersTable.setModel(this.parametersTableModel);
        
        this.axFetchRequestTableModel = new AXFetchRequestTableModel();
        this.axFetchRequestTable.setModel(this.axFetchRequestTableModel);
        
        this.axFetchResponseTableModel = new AXFetchResponseTableModel();
        this.axFetchResponseTable.setModel(this.axFetchResponseTableModel);
    }
    
    private void addTableListeners() {
        this.openIdTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) {
                    return;
                }
                int row = OpenIdPanel.this.openIdTable.getSelectedRow();
                TableModel tm = OpenIdPanel.this.openIdTable.getModel();
                ConversationID id;
                if (row > -1) {
                    id = (ConversationID) tm.getValueAt(
                            row, 0); // UGLY hack! FIXME!!!!
                    OpenIdPanel.this.displayOpenID(id);
                } else {
                    id = null;
                    OpenIdPanel.this.resetDisplay();
                }
                OpenIdPanel.this.showConversationAction.putValue("CONVERSATION", id);
            }
        });
        this.openIdTable.addMouseListener(new MouseAdapter() {
            
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }
            
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }
            
            private void maybeShowPopup(MouseEvent e) {
                int row = OpenIdPanel.this.openIdTable.rowAtPoint(e.getPoint());
                OpenIdPanel.this.openIdTable.getSelectionModel().setSelectionInterval(row, row);
                if (e.isPopupTrigger()) {
                    OpenIdPanel.this.openIdPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
            
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    ActionEvent actionEvent = new ActionEvent(OpenIdPanel.this.openIdTable, 0, (String) OpenIdPanel.this.showConversationAction.getValue(Action.ACTION_COMMAND_KEY));
                    OpenIdPanel.this.showConversationAction.actionPerformed(actionEvent);
                }
            }
        });
    }
    
    public JPanel getPanel() {
        return this;
    }
    
    public Action[] getUrlActions() {
        return null;
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return null;
    }
    
    public Action[] getConversationActions() {
        return null;
    }
    
    public ColumnDataModel[] getConversationColumns() {
        return null;
    }
    
    public String getPluginName() {
        return this.openId.getPluginName();
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        java.awt.GridBagConstraints gridBagConstraints;

        openIdPopupMenu = new javax.swing.JPopupMenu();
        jSplitPane1 = new javax.swing.JSplitPane();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        openIdTable = new javax.swing.JTable();
        jTabbedPane2 = new javax.swing.JTabbedPane();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        parametersTable = new javax.swing.JTable();
        jPanel3 = new javax.swing.JPanel();
        jTabbedPane3 = new javax.swing.JTabbedPane();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane3 = new javax.swing.JScrollPane();
        axFetchRequestTable = new javax.swing.JTable();
        jPanel5 = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        axFetchResponseTable = new javax.swing.JTable();
        jPanel7 = new javax.swing.JPanel();
        jTabbedPane4 = new javax.swing.JTabbedPane();
        jPanel8 = new javax.swing.JPanel();
        jPanel9 = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        papeAuthnTimeLabel = new javax.swing.JLabel();
        jPanel10 = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        phishingResistantCheckBox = new javax.swing.JCheckBox();
        jLabel6 = new javax.swing.JLabel();
        multiFactorCheckBox = new javax.swing.JCheckBox();
        jLabel7 = new javax.swing.JLabel();
        physicalMultiFactorCheckBox = new javax.swing.JCheckBox();
        jLabel8 = new javax.swing.JLabel();
        papeSignedCheckBox = new javax.swing.JCheckBox();
        jPanel6 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();

        setLayout(new java.awt.BorderLayout());

        jSplitPane1.setDividerLocation(150);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        jPanel1.setLayout(new java.awt.BorderLayout());

        openIdTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(openIdTable);

        jPanel1.add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("Messages", jPanel1);

        jSplitPane1.setTopComponent(jTabbedPane1);

        jPanel2.setLayout(new java.awt.BorderLayout());

        parametersTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane2.setViewportView(parametersTable);

        jPanel2.add(jScrollPane2, java.awt.BorderLayout.CENTER);

        jTabbedPane2.addTab("Parameters", jPanel2);

        jPanel3.setLayout(new java.awt.BorderLayout());

        jPanel4.setLayout(new java.awt.BorderLayout());

        axFetchRequestTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane3.setViewportView(axFetchRequestTable);

        jPanel4.add(jScrollPane3, java.awt.BorderLayout.CENTER);

        jTabbedPane3.addTab("Fetch Request", jPanel4);

        jPanel5.setLayout(new java.awt.BorderLayout());

        axFetchResponseTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane4.setViewportView(axFetchResponseTable);

        jPanel5.add(jScrollPane4, java.awt.BorderLayout.CENTER);

        jTabbedPane3.addTab("Fetch Response", jPanel5);

        jPanel3.add(jTabbedPane3, java.awt.BorderLayout.CENTER);

        jTabbedPane2.addTab("Attribute Exchange", jPanel3);

        jPanel7.setLayout(new java.awt.BorderLayout());

        jPanel8.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel9.setLayout(new java.awt.GridBagLayout());

        jLabel4.setText("Authentication time:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        jPanel9.add(jLabel4, gridBagConstraints);

        papeAuthnTimeLabel.setText("       ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel9.add(papeAuthnTimeLabel, gridBagConstraints);

        jPanel10.setBorder(javax.swing.BorderFactory.createTitledBorder("Authentication Policies"));
        jPanel10.setLayout(new java.awt.GridBagLayout());

        jLabel5.setText("Phishing-Resistant Authentication:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel10.add(jLabel5, gridBagConstraints);

        phishingResistantCheckBox.setEnabled(false);
        jPanel10.add(phishingResistantCheckBox, new java.awt.GridBagConstraints());

        jLabel6.setText("Multi-Factor Authentication:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel10.add(jLabel6, gridBagConstraints);

        multiFactorCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        jPanel10.add(multiFactorCheckBox, gridBagConstraints);

        jLabel7.setText("Physical Multi-Factor Authentication:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel10.add(jLabel7, gridBagConstraints);

        physicalMultiFactorCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        jPanel10.add(physicalMultiFactorCheckBox, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 0, 5, 0);
        jPanel9.add(jPanel10, gridBagConstraints);

        jLabel8.setText("Signed:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel9.add(jLabel8, gridBagConstraints);

        papeSignedCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel9.add(papeSignedCheckBox, gridBagConstraints);

        jPanel8.add(jPanel9);

        jTabbedPane4.addTab("Response Parameters", jPanel8);

        jPanel7.add(jTabbedPane4, java.awt.BorderLayout.CENTER);

        jTabbedPane2.addTab("PAPE", jPanel7);

        jPanel6.setLayout(new java.awt.GridBagLayout());

        jLabel1.setText("WebScarab OpenID Plugin");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.insets = new java.awt.Insets(0, 0, 19, 0);
        jPanel6.add(jLabel1, gridBagConstraints);

        jLabel2.setText("Copyright (C) 2011 FedICT");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        jPanel6.add(jLabel2, gridBagConstraints);

        jLabel3.setText("Copyright (C) 2011 Frank Cornelis <info@frankcornelis.be>");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        jPanel6.add(jLabel3, gridBagConstraints);

        jTabbedPane2.addTab("About", jPanel6);

        jSplitPane1.setRightComponent(jTabbedPane2);
        jTabbedPane2.getAccessibleContext().setAccessibleName("");

        add(jSplitPane1, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable axFetchRequestTable;
    private javax.swing.JTable axFetchResponseTable;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JPanel jPanel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTabbedPane jTabbedPane2;
    private javax.swing.JTabbedPane jTabbedPane3;
    private javax.swing.JTabbedPane jTabbedPane4;
    private javax.swing.JCheckBox multiFactorCheckBox;
    private javax.swing.JPopupMenu openIdPopupMenu;
    private javax.swing.JTable openIdTable;
    private javax.swing.JLabel papeAuthnTimeLabel;
    private javax.swing.JCheckBox papeSignedCheckBox;
    private javax.swing.JTable parametersTable;
    private javax.swing.JCheckBox phishingResistantCheckBox;
    private javax.swing.JCheckBox physicalMultiFactorCheckBox;
    // End of variables declaration//GEN-END:variables

    private void displayOpenID(ConversationID id) {
        resetDisplay();
        this.parametersTableModel.setParameters(this.openIdModel.getParameters(id));
        this.axFetchRequestTableModel.setAttributes(this.openIdModel.getAXFetchRequestAttributes(id));
        this.axFetchResponseTableModel.setAttributes(this.openIdModel.getAXFetchResponseAttributes(id));
        PAPEResponse papeResponse = this.openIdModel.getPAPEResponse(id);
        if (null != papeResponse) {
            if (null != papeResponse.getAuthenticationTime()) {
                this.papeAuthnTimeLabel.setText(papeResponse.getAuthenticationTime().toString());
            } else {
                this.papeAuthnTimeLabel.setText("Not provided.");
            }
            this.phishingResistantCheckBox.setSelected(papeResponse.isPhishingResistant());
            this.multiFactorCheckBox.setSelected(papeResponse.isMultiFactor());
            this.physicalMultiFactorCheckBox.setSelected(papeResponse.isMultiFactorPhysical());
            this.papeSignedCheckBox.setSelected(papeResponse.isSigned());
        }
    }
    
    private void resetDisplay() {
        this.parametersTableModel.resetParameters();
        this.axFetchRequestTableModel.resetAttributes();
        this.axFetchResponseTableModel.resetAttributes();
        this.papeAuthnTimeLabel.setText("");
        this.phishingResistantCheckBox.setSelected(false);
        this.multiFactorCheckBox.setSelected(false);
        this.physicalMultiFactorCheckBox.setSelected(false);
        this.papeSignedCheckBox.setSelected(false);
    }
}
