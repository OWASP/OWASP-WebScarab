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
 * FuzzerPanel.java
 *
 * Created on 26 October 2004, 04:41
 */

package org.owasp.webscarab.plugin.fuzz.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.plugin.fuzz.Fuzzer;
import org.owasp.webscarab.plugin.fuzz.FuzzerEvent;
import org.owasp.webscarab.plugin.fuzz.FuzzerListener;
import org.owasp.webscarab.plugin.fuzz.FuzzerModel;
import org.owasp.webscarab.plugin.fuzz.Parameter;
import org.owasp.webscarab.plugin.fuzz.Signature;

import org.owasp.webscarab.util.swing.JTreeTable;
import org.owasp.webscarab.util.swing.ColumnDataModel;

import org.owasp.webscarab.ui.swing.SiteTreeTableModelAdapter;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.ui.swing.UrlTreeRenderer;
import org.owasp.webscarab.util.swing.ColumnDataModel;

import javax.swing.Action;
import javax.swing.JTree;
import javax.swing.tree.TreeSelectionModel;
import javax.swing.tree.TreePath;
import javax.swing.ListSelectionModel;

import javax.swing.table.AbstractTableModel;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;

import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public class FuzzerPanel extends javax.swing.JPanel implements SwingPluginUI {
    
    private Fuzzer _fuzzer;
    private FuzzerModel _model;
    private SiteTreeTableModelAdapter _sttm;
    
    private ColumnDataModel _dynamicColumn;
    private ColumnDataModel _potentialAppColumn;
    private ColumnDataModel _authColumn;
    private ColumnDataModel _errorColumn;
    
    private JTreeTable _siteTreeTable;
    private SignatureTableModel _signatureTableModel;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates new form FuzzerPanel */
    public FuzzerPanel(Fuzzer fuzzer) {
        _fuzzer = fuzzer;
        _model = fuzzer.getModel();
        initComponents();
        _potentialAppColumn = new FuzzerPanel.PotentialAppColumn();
        _dynamicColumn = new FuzzerPanel.DynamicColumn();
        _authColumn = new FuzzerPanel.AuthColumn();
        _errorColumn = new FuzzerPanel.ErrorColumn();
        _model.addModelListener(new Listener());
        
        _signatureTableModel = new SignatureTableModel();
        signatureTable.setModel(_signatureTableModel);
        
        _sttm = new SiteTreeTableModelAdapter(_model);
        _sttm.addColumn(_potentialAppColumn);
        _sttm.addColumn(_dynamicColumn);
        _sttm.addColumn(_authColumn);
        _sttm.addColumn(_errorColumn);
        _siteTreeTable = new JTreeTable(_sttm);
        
        treeScrollPane.getViewport().remove(urlTree);
        urlTree = _siteTreeTable.getTree();
        urlTree.getSelectionModel().setSelectionMode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);
        _siteTreeTable.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        urlTree.setRootVisible(false);
        urlTree.setShowsRootHandles(true);
        urlTree.setCellRenderer(new UrlTreeRenderer());
        
        treeScrollPane.getViewport().add(_siteTreeTable);
        
        urlTree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(TreeSelectionEvent e) {
                HttpUrl url = null;
                TreePath selection = urlTree.getSelectionPath();
                if (selection != null) url = (HttpUrl) selection.getLastPathComponent();
                _signatureTableModel.setUrl(url);
            }
        });
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        jTabbedPane1 = new javax.swing.JTabbedPane();
        jSplitPane1 = new javax.swing.JSplitPane();
        jPanel1 = new javax.swing.JPanel();
        treeScrollPane = new javax.swing.JScrollPane();
        urlTree = new javax.swing.JTree();
        jScrollPane3 = new javax.swing.JScrollPane();
        signatureTable = new javax.swing.JTable();
        jScrollPane1 = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        fuzzTable = new javax.swing.JTable();
        startButton = new javax.swing.JButton();
        stopButton = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        totalTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        remainingTextField = new javax.swing.JTextField();
        jPanel3 = new javax.swing.JPanel();
        testAppButton = new javax.swing.JButton();

        setLayout(new java.awt.BorderLayout());

        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setResizeWeight(0.5);
        jSplitPane1.setContinuousLayout(true);
        jPanel1.setLayout(new java.awt.GridBagLayout());

        treeScrollPane.setViewportView(urlTree);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel1.add(treeScrollPane, gridBagConstraints);

        signatureTable.setModel(new javax.swing.table.DefaultTableModel(
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
        jScrollPane3.setViewportView(signatureTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 0.3;
        jPanel1.add(jScrollPane3, gridBagConstraints);

        jSplitPane1.setLeftComponent(jPanel1);

        conversationTable.setModel(new javax.swing.table.DefaultTableModel(
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
        jScrollPane1.setViewportView(conversationTable);

        jSplitPane1.setRightComponent(jScrollPane1);

        jTabbedPane1.addTab("Apps", jSplitPane1);

        jPanel2.setLayout(new java.awt.GridBagLayout());

        fuzzTable.setModel(new javax.swing.table.DefaultTableModel(
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
        jScrollPane2.setViewportView(fuzzTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel2.add(jScrollPane2, gridBagConstraints);

        startButton.setText("Start");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        jPanel2.add(startButton, gridBagConstraints);

        stopButton.setText("Stop");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 2;
        jPanel2.add(stopButton, gridBagConstraints);

        jLabel1.setText("Total Requests : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        jPanel2.add(jLabel1, gridBagConstraints);

        totalTextField.setColumns(5);
        totalTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        jPanel2.add(totalTextField, gridBagConstraints);

        jLabel2.setText("Remaining Requests : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        jPanel2.add(jLabel2, gridBagConstraints);

        remainingTextField.setColumns(5);
        remainingTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        jPanel2.add(remainingTextField, gridBagConstraints);

        jTabbedPane1.addTab("Fuzz", jPanel2);

        add(jTabbedPane1, java.awt.BorderLayout.CENTER);

        testAppButton.setText("Verify Applications");
        testAppButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                testAppButtonActionPerformed(evt);
            }
        });

        jPanel3.add(testAppButton);

        add(jPanel3, java.awt.BorderLayout.SOUTH);

    }//GEN-END:initComponents

    private void testAppButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_testAppButtonActionPerformed
        if (evt.getActionCommand().equals("Verify Applications")) {
            if (urlTree.getSelectionModel().getSelectionCount() == 0) {
                _logger.info("Nothing selected");
                return;
            } else {
                _logger.info(urlTree.getSelectionModel().getSelectionCount() + " selected");
            }
            testAppButton.setText("Stop");
            TreePath[] selectedPaths = urlTree.getSelectionModel().getSelectionPaths();
            HttpUrl[] selected = new HttpUrl[selectedPaths.length];
            for (int i=0; i<selectedPaths.length; i++) {
                selected[i] = (HttpUrl) selectedPaths[i].getLastPathComponent();
            }
            _fuzzer.queueUrls(selected);
        } else {
            testAppButton.setText("Verify Applications");
            _fuzzer.clearUrlQueue();
        }
    }//GEN-LAST:event_testAppButtonActionPerformed

    public Action[] getConversationActions() {
        return new Action[0];
    }    

    public ColumnDataModel[] getConversationColumns() {
        return new ColumnDataModel[0];
    }
    
    public javax.swing.JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "Fuzzer";
    }
    
    public Action[] getUrlActions() {
        return new Action[0];
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return new ColumnDataModel[] { _potentialAppColumn, _dynamicColumn, _authColumn, _errorColumn };
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable conversationTable;
    private javax.swing.JTable fuzzTable;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTextField remainingTextField;
    private javax.swing.JTable signatureTable;
    private javax.swing.JButton startButton;
    private javax.swing.JButton stopButton;
    private javax.swing.JButton testAppButton;
    private javax.swing.JTextField totalTextField;
    private javax.swing.JScrollPane treeScrollPane;
    private javax.swing.JTree urlTree;
    // End of variables declaration//GEN-END:variables

    private class PotentialAppColumn extends ColumnDataModel {
        
        public PotentialAppColumn() {
        }
        
        public String getColumnName() {
            return "Possible App";
        }
        
        public Class getColumnClass() {
            return Boolean.class;
        }
        
        public Object getValue(Object key) {
            return new Boolean(_model.isAppCandidate((HttpUrl) key));
        }
        
    }
    
    private class DynamicColumn extends ColumnDataModel {
        
        public DynamicColumn() {
        }
        
        public String getColumnName() {
            return "Dynamic";
        }
        
        public Class getColumnClass() {
            return Boolean.class;
        }
        
        public Object getValue(Object key) {
            return new Boolean(_model.hasDynamicContent((HttpUrl) key));
        }
        
    }
    
    private class AuthColumn extends ColumnDataModel {
        
        public AuthColumn() {
        }
        
        public String getColumnName() {
            return "Auth Req?";
        }
        
        public Class getColumnClass() {
            return Boolean.class;
        }
        
        public Object getValue(Object key) {
            return new Boolean(_model.isAuthenticationRequired((HttpUrl) key));
        }
        
    }
    
    private class ErrorColumn extends ColumnDataModel {
        
        public ErrorColumn() {
        }
        
        public String getColumnName() {
            return "Errors";
        }
        
        public Class getColumnClass() {
            return Boolean.class;
        }
        
        public Object getValue(Object key) {
            return new Boolean(_model.hasErrors((HttpUrl) key));
        }
        
    }
    
    private class SignatureTableModel extends AbstractTableModel {
        
        private HttpUrl _url = null;
        private String[] _columnNames = new String[] {"Method", "ContentType", "Parameters" };
        
        public SignatureTableModel() {
        }
        
        public String getColumnName(int columnIndex) {
            return _columnNames[columnIndex];
        }
        
        public void setUrl(HttpUrl url) {
            _url = url;
            fireTableDataChanged();
        }
        
        public HttpUrl getUrl() {
            return _url;
        }
        
        public int getColumnCount() {
            return 3;
        }
        
        public int getRowCount() {
            if (_url == null) return 0;
            return _model.getSignatureCount(_url);
        }
        
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (_url == null) return null;
            Signature signature = _model.getSignature(_url, rowIndex);
            switch (columnIndex) {
                case 0: return signature.getMethod();
                case 1: return signature.getContentType();
                case 2: 
                    Parameter[] parameters = signature.getParameters();
                    StringBuffer buff = new StringBuffer();
                    for (int i=0; i< parameters.length; i++) {
                        buff.append(parameters[i].getName()).append("[").append(parameters[i].getLocation()).append("] ");
                    }
                    return buff.toString();
            }
            return null;
        }
        
    }
    
    private class Listener extends FuzzerListener {
        
        public Listener() {
        }
        
        public void appStatusChanged(FuzzerEvent evt) {
            HttpUrl url = evt.getUrl();
            _logger.info("AppStatus Changed " + url);
            _dynamicColumn.fireValueChanged(url);
            _potentialAppColumn.fireValueChanged(url);
        }
        
        public void signatureAdded(FuzzerEvent evt) {
            HttpUrl url = evt.getUrl();
            _potentialAppColumn.fireValueChanged(url);
            _dynamicColumn.fireValueChanged(url);
            HttpUrl selected = _signatureTableModel.getUrl();
            if (selected != null && selected.equals(url)) 
                _signatureTableModel.fireTableDataChanged();
        }
        
        public void authenticationRequired(FuzzerEvent evt) {
            HttpUrl url = evt.getUrl();
            _authColumn.fireValueChanged(url);
        }
        
        public void urlError(FuzzerEvent evt) {
            HttpUrl url = evt.getUrl();
            _errorColumn.fireValueChanged(url);
        }
        
        public void fuzzerStarted(FuzzerEvent evt) {
        }
        
        public void fuzzerStopped(FuzzerEvent evt) {
        }
        
    }
    
}
