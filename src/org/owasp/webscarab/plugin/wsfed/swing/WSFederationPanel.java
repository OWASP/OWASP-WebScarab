/***********************************************************************
 *
 * $CVSHeader$
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
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */
package org.owasp.webscarab.plugin.wsfed.swing;

import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.Action;
import javax.swing.JPanel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.plugin.saml.swing.AttributesTableModel;
import org.owasp.webscarab.plugin.wsfed.WSFederation;
import org.owasp.webscarab.plugin.wsfed.WSFederationModel;
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
public class WSFederationPanel extends javax.swing.JPanel implements SwingPluginUI {

    private final WSFederation wsfed;
    private final WSFederationModel wsfedModel;
    private final ParametersTableModel parametersTableModel;
    private final ShowConversationAction showConversationAction;
    private final AttributesTableModel samlAttributesTableModel;

    /** Creates new form WSFederationPanel */
    public WSFederationPanel(WSFederation wsfed) {
        this.wsfed = wsfed;
        this.wsfedModel = wsfed.getModel();
        initComponents();

        this.showConversationAction = new ShowConversationAction(this.wsfedModel.getConversationModel());
        this.wsfedPopupMenu.add(this.showConversationAction);

        ConversationTableModel wsfedTableModel = new ConversationTableModel(
                this.wsfedModel.getConversationModel());
        wsfedTableModel.addColumn(new ColumnDataModel<ConversationID>("WS-Federation", String.class) {
            @Override
            public Object getValue(ConversationID key) {
                return WSFederationPanel.this.wsfedModel.getReadableMessageType(key);
            }
        });
        ColumnWidthTracker.getTracker("WSFederationTable").addTable(this.conversationsTable);
        TableSorter sorterWSFederationTableModel = new TableSorter(wsfedTableModel);
        this.conversationsTable.setModel(sorterWSFederationTableModel);
        addTableListeners();

        this.parametersTableModel = new ParametersTableModel();
        this.parametersTable.setModel(this.parametersTableModel);
        
        this.samlAttributesTableModel = new AttributesTableModel();
        this.samlAttributesTable.setModel(this.samlAttributesTableModel);
    }

    private void addTableListeners() {
        this.conversationsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) {
                    return;
                }
                int row = WSFederationPanel.this.conversationsTable.getSelectedRow();
                TableModel tm = WSFederationPanel.this.conversationsTable.getModel();
                ConversationID id;
                if (row > -1) {
                    id = (ConversationID) tm.getValueAt(
                            row, 0); // UGLY hack! FIXME!!!!
                    WSFederationPanel.this.display(id);
                } else {
                    id = null;
                    WSFederationPanel.this.resetDisplay();
                }
                WSFederationPanel.this.showConversationAction.putValue("CONVERSATION", id);
            }
        });
        this.conversationsTable.addMouseListener(new MouseAdapter() {

            @Override
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }

            private void maybeShowPopup(MouseEvent e) {
                int row = WSFederationPanel.this.conversationsTable.rowAtPoint(e.getPoint());
                WSFederationPanel.this.conversationsTable.getSelectionModel().setSelectionInterval(row, row);
                if (e.isPopupTrigger()) {
                    WSFederationPanel.this.wsfedPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    ActionEvent actionEvent = new ActionEvent(WSFederationPanel.this.conversationsTable, 0, (String) WSFederationPanel.this.showConversationAction.getValue(Action.ACTION_COMMAND_KEY));
                    WSFederationPanel.this.showConversationAction.actionPerformed(actionEvent);
                }
            }
        });
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

        wsfedPopupMenu = new javax.swing.JPopupMenu();
        jSplitPane1 = new javax.swing.JSplitPane();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        parametersTable = new javax.swing.JTable();
        jPanel4 = new javax.swing.JPanel();
        xmlPanel = new org.owasp.webscarab.ui.swing.editors.XMLPanel();
        jPanel5 = new javax.swing.JPanel();
        jTabbedPane3 = new javax.swing.JTabbedPane();
        jPanel6 = new javax.swing.JPanel();
        assertionPanel = new org.owasp.webscarab.ui.swing.editors.XMLPanel();
        jPanel7 = new javax.swing.JPanel();
        jPanel8 = new javax.swing.JPanel();
        jScrollPane3 = new javax.swing.JScrollPane();
        samlAttributesTable = new javax.swing.JTable();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jTabbedPane2 = new javax.swing.JTabbedPane();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        conversationsTable = new javax.swing.JTable();

        setLayout(new java.awt.BorderLayout());

        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        jPanel3.setLayout(new java.awt.BorderLayout());

        jScrollPane2.setViewportView(parametersTable);

        jPanel3.add(jScrollPane2, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("Parameters", jPanel3);

        jPanel4.setLayout(new java.awt.BorderLayout());
        jPanel4.add(xmlPanel, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("XML", jPanel4);

        jPanel5.setLayout(new java.awt.BorderLayout());

        jPanel6.setLayout(new java.awt.BorderLayout());
        jPanel6.add(assertionPanel, java.awt.BorderLayout.CENTER);

        jTabbedPane3.addTab("XML", jPanel6);
        jTabbedPane3.addTab("Signature", jPanel7);

        jPanel8.setLayout(new java.awt.BorderLayout());

        jScrollPane3.setViewportView(samlAttributesTable);

        jPanel8.add(jScrollPane3, java.awt.BorderLayout.CENTER);

        jTabbedPane3.addTab("Attributes", jPanel8);

        jPanel5.add(jTabbedPane3, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("SAML Assertion", jPanel5);

        jPanel1.setLayout(new java.awt.GridBagLayout());

        jLabel1.setText("WebScarab WS-Federation Plugin");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new java.awt.Insets(0, 0, 20, 0);
        jPanel1.add(jLabel1, gridBagConstraints);

        jLabel2.setText("Copyright (C) 2011 Frank Cornelis <info@frankcornelis.be>");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        jPanel1.add(jLabel2, gridBagConstraints);

        jLabel3.setText("Copyright (C) 2011 FedICT");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        jPanel1.add(jLabel3, gridBagConstraints);

        jTabbedPane1.addTab("About", jPanel1);

        jSplitPane1.setBottomComponent(jTabbedPane1);

        jPanel2.setLayout(new java.awt.BorderLayout());

        jScrollPane1.setViewportView(conversationsTable);

        jPanel2.add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jTabbedPane2.addTab("Web Passive Requestor Messages", jPanel2);

        jSplitPane1.setTopComponent(jTabbedPane2);

        add(jSplitPane1, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private org.owasp.webscarab.ui.swing.editors.XMLPanel assertionPanel;
    private javax.swing.JTable conversationsTable;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTabbedPane jTabbedPane2;
    private javax.swing.JTabbedPane jTabbedPane3;
    private javax.swing.JTable parametersTable;
    private javax.swing.JTable samlAttributesTable;
    private javax.swing.JPopupMenu wsfedPopupMenu;
    private org.owasp.webscarab.ui.swing.editors.XMLPanel xmlPanel;
    // End of variables declaration//GEN-END:variables

    @Override
    public JPanel getPanel() {
        return this;
    }

    @Override
    public Action[] getUrlActions() {
        return null;
    }

    @Override
    public ColumnDataModel<HttpUrl>[] getUrlColumns() {
        return null;
    }

    @Override
    public Action[] getConversationActions() {
        return null;
    }

    @Override
    public ColumnDataModel<ConversationID>[] getConversationColumns() {
        return null;
    }

    @Override
    public String getPluginName() {
        return this.wsfed.getPluginName();
    }

    private void display(ConversationID id) {
        resetDisplay();

        List parameters = this.wsfedModel.getParameters(id);
        this.parametersTableModel.setParameters(parameters);
        Iterator parameterIter = parameters.iterator();
        while (parameterIter.hasNext()) {
            NamedValue parameter = (NamedValue) parameterIter.next();
            if ("wreq".equals(parameter.getName())) {
                this.xmlPanel.setBytes("text/xml", parameter.getValue().getBytes());
                break;
            }
            if ("wresult".equals(parameter.getName())) {
                this.xmlPanel.setBytes("text/xml", parameter.getValue().getBytes());
                try {
                    byte[] assertion = this.wsfedModel.findSAMLAssertion(parameter.getValue().getBytes());
                    if (null != assertion) {
                        this.assertionPanel.setBytes("text/xml", assertion);
                        List samlAttributes = this.wsfedModel.getSAMLAttributes(assertion);
                        this.samlAttributesTableModel.setAttributes(samlAttributes);
                    }
                } catch (Exception ex) {
                    Logger.getLogger(WSFederationPanel.class.getName()).log(Level.SEVERE, null, ex);
                }
                break;
            }
        }
    }

    private void resetDisplay() {
        this.parametersTableModel.resetParameters();
        this.xmlPanel.setBytes(null, null);
        this.assertionPanel.setBytes(null, null);
        this.samlAttributesTableModel.resetAttributes();
    }
}
