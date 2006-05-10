/*
 * ComparePanel.java
 *
 * Created on 18 May 2005, 06:15
 */

package org.owasp.webscarab.plugin.compare.swing;

import java.util.List;
import javax.swing.JOptionPane;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.compare.Compare;
import org.owasp.webscarab.plugin.compare.CompareModel;

import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.ui.swing.ConversationListModel;
import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.ui.swing.ContentPanel;
import org.owasp.webscarab.util.Diff;

import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.SwingWorker;
import org.owasp.webscarab.util.swing.TableSorter;
import org.owasp.webscarab.util.swing.ListComboBoxModel;
import org.owasp.webscarab.util.swing.DiffPanel;
import org.owasp.webscarab.ui.swing.ConversationRenderer;
import org.owasp.webscarab.ui.swing.DateRenderer;

import javax.swing.JPanel;
import javax.swing.Action;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.util.Date;

/**
 *
 * @author  rogan
 */
public class ComparePanel extends javax.swing.JPanel implements SwingPluginUI {
    
    private Compare _compare;
    private CompareModel _model;
    private ConversationTableModel _tableModel;
    private TableSorter _conversationSorter;
    private DiffPanel _diffPanel;
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _base = null;
    
    /** Creates new form ComparePanel */
    public ComparePanel(Compare compare) {
        initComponents();
        _compare = compare;
        _model = _compare.getModel();
        baseComboBox.setModel(new ListComboBoxModel(new ConversationListModel(_model.getConversationModel())));
        baseComboBox.setRenderer(new ConversationRenderer(_model.getConversationModel()));
        _tableModel = new ConversationTableModel(_model.getComparisonModel());
        _tableModel.addColumn(new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getDistance((ConversationID) key);
            }
            public String getColumnName() { return "Distance"; }
            public Class getColumnClass() { return Integer.class; }
        });
        
        conversationTable.setDefaultRenderer(Date.class, new DateRenderer());
        _conversationSorter = new TableSorter(_tableModel, conversationTable.getTableHeader());
        conversationTable.setModel(_conversationSorter);
        _diffPanel = new DiffPanel();
        compareSplitPane.setBottomComponent(_diffPanel);
    
        baseComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Object o = baseComboBox.getSelectedItem();
                if (o instanceof ConversationID) {
                    ConversationID id = (ConversationID) o;
                    ConversationModel cModel = _model.getConversationModel();
                    Response response = cModel.getResponse(id);
                    String cType = response.getHeader("Content-Type");
                    if (cType == null || !cType.startsWith("text")) {
                        JOptionPane.showMessageDialog(ComparePanel.this, "Selected conversation is not text", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    byte[] content = response.getContent();
                    if (content == null || content.length == 0) {
                        JOptionPane.showMessageDialog(ComparePanel.this, "Selected conversation has no content", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    _compare.setBaseConversation(null, id);
                    _base = new String(content);
                }
            }
        });
        
        conversationTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                int selected = conversationTable.getSelectedRow();
                _diffPanel.clear();
                if (selected == -1) {
                    return;
                }
                selected = _conversationSorter.modelIndex(selected);
                ConversationModel cmodel = _model.getComparisonModel();
                
                ConversationID id = cmodel.getConversationAt(selected);
                Response response = cmodel.getResponse(id);
                String contentType = response.getHeader("Content-Type");
                if (contentType == null || !contentType.startsWith("text")) {
                    JOptionPane.showMessageDialog(ComparePanel.this, "Selected conversation is not text", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                byte[] content = response.getContent();
                if (content == null || content.length == 0) {
                    JOptionPane.showMessageDialog(ComparePanel.this, "Selected conversation has no content", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                final String dst = new String(content);
                new SwingWorker() {
                    public Object construct() {
                        return Diff.getEdits(_base, dst);
                    }
                    public void finished() {
                        List edits = (List) get();
                        _diffPanel.showDifferences(_base, dst, edits);
                    }
                }.start();
            }
        });
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        baseComboBox = new javax.swing.JComboBox();
        compareSplitPane = new javax.swing.JSplitPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();

        setLayout(new java.awt.BorderLayout());

        baseComboBox.setMaximumSize(null);
        add(baseComboBox, java.awt.BorderLayout.NORTH);

        compareSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        compareSplitPane.setResizeWeight(0.3);
        compareSplitPane.setOneTouchExpandable(true);
        conversationTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane1.setViewportView(conversationTable);

        compareSplitPane.setLeftComponent(jScrollPane1);

        add(compareSplitPane, java.awt.BorderLayout.CENTER);

    }// </editor-fold>//GEN-END:initComponents

    public Action[] getConversationActions() {
        return new Action[0];
    }    
    
    public ColumnDataModel[] getConversationColumns() {
        return new ColumnDataModel[0];
    }    
    
    public JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "Compare";
    }
    
    public Action[] getUrlActions() {
        return new Action[0];
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return new ColumnDataModel[0];
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox baseComboBox;
    private javax.swing.JSplitPane compareSplitPane;
    private javax.swing.JTable conversationTable;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
    
}
