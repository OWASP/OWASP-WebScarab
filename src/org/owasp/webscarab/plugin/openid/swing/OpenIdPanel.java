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

        jSplitPane1.setRightComponent(jTabbedPane2);
        jTabbedPane2.getAccessibleContext().setAccessibleName("");

        add(jSplitPane1, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable axFetchRequestTable;
    private javax.swing.JTable axFetchResponseTable;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTabbedPane jTabbedPane2;
    private javax.swing.JTabbedPane jTabbedPane3;
    private javax.swing.JPopupMenu openIdPopupMenu;
    private javax.swing.JTable openIdTable;
    private javax.swing.JTable parametersTable;
    // End of variables declaration//GEN-END:variables

    private void displayOpenID(ConversationID id) {
        this.parametersTableModel.setParameters(this.openIdModel.getParameters(id));
        this.axFetchRequestTableModel.setAttributes(this.openIdModel.getAXFetchRequestAttributes(id));
    }

    private void resetDisplay() {
        this.parametersTableModel.resetParameters();
        this.axFetchRequestTableModel.resetAttributes();
    }
}
