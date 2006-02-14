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
 * SummaryPanel.java
 *
 * Created on December 16, 2003, 10:35 AM
 */

package org.owasp.webscarab.ui.swing;

import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTree;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.TableModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredUrlModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.JTreeTable;
import org.owasp.webscarab.util.swing.TableSorter;

/**
 *
 * @author  rdawes
 */
public class SummaryPanel extends JPanel {
    
    private FrameworkModel _model;
    private UrlFilteredConversationModel _conversationModel;
    private FilteredUrlModel _urlModel;
    private JTreeTable _urlTreeTable;
    private ArrayList _urlActions = new ArrayList();
    private HttpUrl _treeURL = null;
    private TableSorter _conversationTableSorter;
    private ConversationTableModel _conversationTableModel;
    private UrlTreeTableModelAdapter _urlTreeTableModel;
    private ArrayList _conversationActions = new ArrayList();
    
    private Map _urlColumns = new HashMap();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates new form SummaryPanel */
    public SummaryPanel(FrameworkModel model) {
        _model = model;
        _conversationModel = new UrlFilteredConversationModel(_model, _model.getConversationModel());
        // FIXME this is the wrong place for this, I think?
        _urlModel = new FilteredUrlModel(model.getUrlModel()) {
            protected boolean shouldFilter(HttpUrl url) {
                return _model.getUrlProperty(url, "METHODS") == null;
            }
        };
        initComponents();
        
        initTree();
        addTreeListeners();
        
        initTable();
        addTableListeners();
        addConversationActions(new Action[] {
            new ShowConversationAction(_conversationModel)
        });
    }
    
    private void initTree() {
        _urlTreeTableModel = new UrlTreeTableModelAdapter(_urlModel);
        _urlTreeTable = new JTreeTable(_urlTreeTableModel);
        _urlTreeTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        ColumnWidthTracker.getTracker("UrlTree").addTable(_urlTreeTable);
        
        ColumnDataModel cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getUrlProperty((HttpUrl) key, "METHODS");
            }
            public String getColumnName() { return "Methods"; }
            public Class getColumnClass() { return String.class; }
        };
        _urlColumns.put("METHODS", cdm);
        _urlTreeTableModel.addColumn(cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getUrlProperty((HttpUrl) key, "STATUS");
            }
            public String getColumnName() { return "Status"; }
            public Class getColumnClass() { return String.class; }
        };
        _urlColumns.put("STATUS", cdm);
        _urlTreeTableModel.addColumn(cdm);
        
        JTree urlTree = _urlTreeTable.getTree();
        urlTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        urlTree.setRootVisible(false);
        urlTree.setShowsRootHandles(true);
        urlTree.setCellRenderer(new UrlTreeRenderer());
        
        treeScrollPane.setViewportView(_urlTreeTable);
    }
    
    private void addTreeListeners() {
        // Listen for when the selection changes.
        // We use this to set the selected URLInfo for each action, and
        // to filter the conversation list
        final JTree urlTree = _urlTreeTable.getTree();
        urlTree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(TreeSelectionEvent e) {
                TreePath selection = urlTree.getSelectionPath();
                _treeURL = null;
                if (selection != null) {
                    Object o = selection.getLastPathComponent();
                    if (o instanceof HttpUrl) {
                        _treeURL = (HttpUrl) o;
                    }
                }
                if (treeCheckBox.isSelected()) {
                    _conversationModel.setUrl(_treeURL);
                }
                synchronized (_urlActions) {
                    for (int i=0; i<_urlActions.size(); i++) {
                        AbstractAction action = (AbstractAction) _urlActions.get(i);
                        action.putValue("URL", _treeURL);
                    }
                }
            }
        });
        _urlTreeTable.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }
            private void maybeShowPopup(MouseEvent e) {
                if (e.isPopupTrigger() && _urlActions.size() > 0) {
                    int row = _urlTreeTable.rowAtPoint(e.getPoint());
                    _urlTreeTable.getSelectionModel().setSelectionInterval(row,row);
                    urlPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }
    
    public void addUrlActions(Action[] actions) {
        if (actions == null) return;
        for (int i=0; i<actions.length; i++) {
            _urlActions.add(actions[i]);
        }
        for (int i=0; i<actions.length; i++) {
            urlPopupMenu.add(new JMenuItem(actions[i]));
        }
    }
    
    public void addUrlColumns(ColumnDataModel[] columns) {
        if (columns == null) return;
        for (int i=0; i<columns.length; i++) {
            _urlTreeTableModel.addColumn(columns[i]);
        }
    }
    
    private void initTable() {
        _conversationTableModel = new ConversationTableModel(_conversationModel);
        ColumnWidthTracker.getTracker("ConversationTable").addTable(conversationTable);
        
        _conversationTableSorter = new TableSorter(_conversationTableModel, conversationTable.getTableHeader());
        conversationTable.setModel(_conversationTableSorter);
        
        conversationTable.setDefaultRenderer(Date.class, new DateRenderer());
    }
    
    private void addTableListeners() {
        // This listener updates the registered actions with the selected Conversation
        conversationTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) return;
                int row = conversationTable.getSelectedRow();
                TableModel tm = conversationTable.getModel();
                ConversationID id = null;
                if (row >-1)
                    id = (ConversationID) tm.getValueAt(row, 0); // UGLY hack! FIXME!!!!
                synchronized (_conversationActions) {
                    for (int i=0; i<_conversationActions.size(); i++) {
                        Action action = (Action) _conversationActions.get(i);
                        action.putValue("CONVERSATION", id);
                    }
                }
            }
        });
        
        conversationTable.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }
            private void maybeShowPopup(MouseEvent e) {
                int row = conversationTable.rowAtPoint(e.getPoint());
                conversationTable.getSelectionModel().setSelectionInterval(row,row);
                if (e.isPopupTrigger() && _conversationActions.size() > 0) {
                    conversationPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    if (_conversationActions.size()>0) {
                        Action action = (Action) _conversationActions.get(0);
                        ActionEvent evt = new ActionEvent(conversationTable, 0, (String) action.getValue(Action.ACTION_COMMAND_KEY));
                        if (action.isEnabled()) {
                            action.actionPerformed(evt);
                        }
                    }
                }
            }
        });
        
    }
    
    public void addConversationActions(Action[] actions) {
        if (actions == null) return;
        for (int i=0; i<actions.length; i++) {
            _conversationActions.add(actions[i]);
        }
        for (int i=0; i<actions.length; i++) {
            conversationPopupMenu.add(new JMenuItem(actions[i]));
        }
    }
    
    public void addConversationColumns(ColumnDataModel[] columns) {
        if (columns == null) return;
        for (int i=0; i<columns.length; i++) {
            _conversationTableModel.addColumn(columns[i]);
        }
        _conversationTableSorter.setSortingStatus(0, TableSorter.DESCENDING);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        urlPopupMenu = new javax.swing.JPopupMenu();
        conversationPopupMenu = new javax.swing.JPopupMenu();
        summarySplitPane = new javax.swing.JSplitPane();
        urlPanel = new javax.swing.JPanel();
        treeCheckBox = new javax.swing.JCheckBox();
        treeScrollPane = new javax.swing.JScrollPane();
        conversationScrollPane = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();

        urlPopupMenu.setLabel("URL Actions");
        conversationPopupMenu.setLabel("Conversation Actions");

        setLayout(new java.awt.BorderLayout());

        summarySplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        summarySplitPane.setResizeWeight(0.5);
        summarySplitPane.setOneTouchExpandable(true);
        urlPanel.setLayout(new java.awt.GridBagLayout());

        urlPanel.setMinimumSize(new java.awt.Dimension(283, 100));
        urlPanel.setPreferredSize(new java.awt.Dimension(264, 100));
        treeCheckBox.setText("Tree Selection filters conversation list");
        treeCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                treeCheckBoxActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        urlPanel.add(treeCheckBox, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        urlPanel.add(treeScrollPane, gridBagConstraints);

        summarySplitPane.setLeftComponent(urlPanel);

        conversationTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        conversationTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        conversationScrollPane.setViewportView(conversationTable);

        summarySplitPane.setRightComponent(conversationScrollPane);

        add(summarySplitPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    private void treeCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_treeCheckBoxActionPerformed
        if (treeCheckBox.isSelected() && _treeURL != null) {
            _conversationModel.setUrl(_treeURL);
        } else {
            _conversationModel.setUrl(null);
        }
    }//GEN-LAST:event_treeCheckBoxActionPerformed
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPopupMenu conversationPopupMenu;
    private javax.swing.JScrollPane conversationScrollPane;
    private javax.swing.JTable conversationTable;
    private javax.swing.JSplitPane summarySplitPane;
    private javax.swing.JCheckBox treeCheckBox;
    private javax.swing.JScrollPane treeScrollPane;
    private javax.swing.JPanel urlPanel;
    private javax.swing.JPopupMenu urlPopupMenu;
    // End of variables declaration//GEN-END:variables
    
    
}
