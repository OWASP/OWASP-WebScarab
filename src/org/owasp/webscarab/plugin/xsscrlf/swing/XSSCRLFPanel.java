/*
 * ExtensionsPanel.java
 *
 * Created on 05 December 2005, 08:41
 */

package org.owasp.webscarab.plugin.xsscrlf.swing;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.logging.Logger;
import javax.swing.Action;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.table.TableModel;
import javax.swing.tree.TreePath;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.plugin.xsscrlf.XSSCRLF;
import org.owasp.webscarab.plugin.xsscrlf.XSSCRLFModel;
import org.owasp.webscarab.ui.swing.ColumnWidthTracker;
import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.ui.swing.DateRenderer;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.ui.swing.UrlTreeModelAdapter;
import org.owasp.webscarab.ui.swing.UrlTreeRenderer;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.SwingWorker;
import org.owasp.webscarab.util.swing.TableSorter;
import org.owasp.webscarab.model.ConversationID;
/**
 *
 * @author  rdawes
 */
public class XSSCRLFPanel extends javax.swing.JPanel implements SwingPluginUI {
    
    private XSSCRLF _xsscrlf;
    private XSSCRLFModel _model;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private ColumnDataModel[] _vulnerableConversationColumns;
    
    private ColumnDataModel[] _vulnerableUrlColumns;
    
    /** Creates new form XSSCRLFPanel */
    public XSSCRLFPanel(XSSCRLF xsscrlf) {
        _xsscrlf = xsscrlf;
        _model = xsscrlf.getModel();
        initComponents();
        
        _vulnerableConversationColumns = new ColumnDataModel[2];
        ConversationTableModel vtm = new ConversationTableModel(_model.getVulnerableConversationModel());
        _vulnerableConversationColumns = new ColumnDataModel[] {
            new ColumnDataModel() {
                public String getColumnName() {
                    return "Possible Injection";
                }
                public Object getValue(Object key) {
                    ConversationID id = (ConversationID) key;
                    return _model.isXSSSuspected(id) || _model.isCRLFSuspected(id)? Boolean.TRUE : Boolean.FALSE;
                }
                public Class getColumnClass() {
                    return Boolean.class;
                }
            }, 
            new ColumnDataModel() {
                public String getColumnName() {
                    return "XSS";
                }
                public Object getValue(Object key) {
                    return _model.isXSSVulnerable((ConversationID) key) ? Boolean.TRUE : Boolean.FALSE;
                }
                public Class getColumnClass() {
                    return Boolean.class;
                }
            }, 
            new ColumnDataModel() {
                public String getColumnName() {
                    return "CRLF";
                }
                public Object getValue(Object key) {
                    return _model.isCRLFVulnerable((ConversationID) key) ? Boolean.TRUE : Boolean.FALSE;
                }
                public Class getColumnClass() {
                    return Boolean.class;
                }
            }
        };
        vtm.addColumn(_vulnerableConversationColumns[0]);
        vtm.addColumn(_vulnerableConversationColumns[1]);
        
        ConversationTableModel stm = new ConversationTableModel(_model.getSuspectedConversationModel());
        stm.addColumn(new ColumnDataModel() {
            public String getColumnName() {
                return "XSS";
            }
            public Object getValue(Object key) {
                return _model.isXSSSuspected((ConversationID) key) ? Boolean.TRUE : Boolean.FALSE;
            }
            public Class getColumnClass() {
                return Boolean.class;
            }
        });
        stm.addColumn(new ColumnDataModel() {
            public String getColumnName() {
                return "CRLF";
            }
            public Object getValue(Object key) {
                return _model.isCRLFSuspected((ConversationID) key) ? Boolean.TRUE : Boolean.FALSE;
            }
            public Class getColumnClass() {
                return Boolean.class;
            }
        });
        
        TableSorter vts = new TableSorter(vtm, conversationTable.getTableHeader());
        TableSorter sts = new TableSorter(stm, suspectedTable.getTableHeader());
        
        conversationTable.setModel(vts);
        suspectedTable.setModel(sts);        
        
        ColumnWidthTracker.getTracker("ConversationTable").addTable(conversationTable);
        ColumnWidthTracker.getTracker("ConversationTable").addTable(suspectedTable);
        
        conversationTable.setDefaultRenderer(Date.class, new DateRenderer());
        suspectedTable.setDefaultRenderer(Date.class, new DateRenderer());
        
        _vulnerableUrlColumns = new ColumnDataModel[] { 
            new ColumnDataModel() {
                public String getColumnName() {
                    return "Possible Injection";
                }
                public Object getValue(Object key) {
                    HttpUrl url = (HttpUrl) key;
                    return _model.isSuspected(url) ? Boolean.TRUE :  Boolean.FALSE;
                }
                public Class getColumnClass() {
                    return Boolean.class;
                }
            }, 
            new ColumnDataModel() {
                public String getColumnName() {
                    return "Injection";
                }
                public Object getValue(Object key) {
                    HttpUrl url = (HttpUrl) key;
                    return _model.isXSSVulnerable(url) || _model.isCRLFVulnerable(url)? Boolean.TRUE :  Boolean.FALSE;
                }
                public Class getColumnClass() {
                    return Boolean.class;
                }
            }

        };
        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        editDialog.setBounds((screenSize.width-300)/2, (screenSize.height-150)/2, 300, 150);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        java.awt.GridBagConstraints gridBagConstraints;

        editDialog = new javax.swing.JDialog();
        tabbedPane = new javax.swing.JTabbedPane();
        jScrollPane4 = new javax.swing.JScrollPane();
        xssTextArea = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        crlfTextArea = new javax.swing.JTextArea();
        jPanel3 = new javax.swing.JPanel();
        loadButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        okButton = new javax.swing.JButton();
        jScrollBar1 = new javax.swing.JScrollBar();
        jSplitPane1 = new javax.swing.JSplitPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        suspectedTable = new javax.swing.JTable();
        jScrollPane2 = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();
        controlPanel = new javax.swing.JPanel();
        editButton = new javax.swing.JButton();
        checkButton = new javax.swing.JButton();

        editDialog.setTitle("Extensions");
        editDialog.setModal(true);
        tabbedPane.setMinimumSize(new java.awt.Dimension(200, 200));
        tabbedPane.setPreferredSize(new java.awt.Dimension(200, 200));
        jScrollPane4.setViewportView(xssTextArea);

        tabbedPane.addTab("XSS", jScrollPane4);

        jScrollPane3.setViewportView(crlfTextArea);

        tabbedPane.addTab("CRLF Injection", jScrollPane3);

        editDialog.getContentPane().add(tabbedPane, java.awt.BorderLayout.CENTER);

        loadButton.setText("Load");
        loadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadButtonActionPerformed(evt);
            }
        });

        jPanel3.add(loadButton);

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        jPanel3.add(cancelButton);

        okButton.setText("Ok");
        okButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButtonActionPerformed(evt);
            }
        });

        jPanel3.add(okButton);

        editDialog.getContentPane().add(jPanel3, java.awt.BorderLayout.SOUTH);

        setLayout(new java.awt.BorderLayout());

        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setResizeWeight(0.5);
        suspectedTable.setModel(new javax.swing.table.DefaultTableModel(
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
        jScrollPane1.setViewportView(suspectedTable);

        jSplitPane1.setLeftComponent(jScrollPane1);

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
        conversationTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        jScrollPane2.setViewportView(conversationTable);

        jSplitPane1.setRightComponent(jScrollPane2);

        add(jSplitPane1, java.awt.BorderLayout.CENTER);

        controlPanel.setLayout(new java.awt.GridBagLayout());

        editButton.setText("Edit Test Strings");
        editButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        controlPanel.add(editButton, gridBagConstraints);

        checkButton.setText("Check");
        checkButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                checkButtonActionPerformed(evt);
            }
        });

        controlPanel.add(checkButton, new java.awt.GridBagConstraints());

        add(controlPanel, java.awt.BorderLayout.SOUTH);

    }
    // </editor-fold>//GEN-END:initComponents

    private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
        _model.setCRLFTestString(crlfTextArea.getText());
        _model.setXSSTestString(xssTextArea.getText());
        editDialog.setVisible(false);
    }//GEN-LAST:event_okButtonActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        editDialog.setVisible(false);
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void loadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadButtonActionPerformed
        JFileChooser jfc = new JFileChooser(Preferences.getPreference("XSSCRLF.DefaultDir"));
        jfc.setDialogTitle("Open test string file");
        int returnVal = jfc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File extFile = jfc.getSelectedFile();
            try {
                String testString=_xsscrlf.loadString(extFile);
                if (tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()).equals("XSS")) {
                    xssTextArea.setText(testString);
                } else {
                    crlfTextArea.setText(testString);
                }
            } catch (IOException ioe) {
                JOptionPane.showMessageDialog(null, new String[] {"Error loading test string: ", ioe.getMessage()}, "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
        Preferences.setPreference("XSSCRLF.DefaultDir", jfc.getCurrentDirectory().getAbsolutePath());
    }//GEN-LAST:event_loadButtonActionPerformed
    
    private void editButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
        xssTextArea.setText(_model.getXSSTestString());
        crlfTextArea.setText(_model.getCRLFTestString());
        editDialog.setVisible(true);
    }//GEN-LAST:event_editButtonActionPerformed
    
    private void checkButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_checkButtonActionPerformed
        
        String action = evt.getActionCommand();
        if (action.equals("Stop")) {
            _xsscrlf.stopChecks();
            return;
        }

        final int[] selection = suspectedTable.getSelectedRows();
         // XXX meder: selection in tables is buggy for now assume that all URLs were selected

//      final int[] selection = new int[suspectedTable.getRowCount()];
//      for(int k=0; k < selection.length; k++) selection[k]=k;
        
        if (selection == null || selection.length == 0) return;
        if (_xsscrlf.isBusy()) {
            showBusyMessage();
            return;
        }
        
        final ConversationID[] CIDs = new ConversationID[selection.length];
        TableModel tm = suspectedTable.getModel();
        ConversationID id = null;         
        
        for (int i=0; i<selection.length; i++) {
            CIDs[i]= (ConversationID) tm.getValueAt(i,0); // UGLY hack! FIXME!!!!            
        }
                       
        checkButton.setText("Stop");
        new SwingWorker() {
            public Object construct() {                
                    _xsscrlf.checkSelected(CIDs);                    
                    return null;
                
            }
            public void finished() {
                Object result = getValue();
                if (result != null && result instanceof Throwable) {
                    Throwable throwable = (Throwable) result;
                    _logger.warning("Caught a : " + throwable.toString());
                }
                checkButton.setText("Check");
            }
        }.start();
    }//GEN-LAST:event_checkButtonActionPerformed
            
    private void showBusyMessage() {
        _logger.warning("Plugin is still busy, please wait");
        // FIXME show a message dialog
    }
    
    public Action[] getConversationActions() {
        return null;
    }

    public ColumnDataModel[] getConversationColumns() {
        return _vulnerableConversationColumns;
    }

    public javax.swing.JPanel getPanel() {
        return this;
    }

    public String getPluginName() {
        return _xsscrlf.getPluginName();
    }

    public Action[] getUrlActions() {
        return null;
    }

    public ColumnDataModel[] getUrlColumns() {
        return _vulnerableUrlColumns;
    }

    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelButton;
    private javax.swing.JButton checkButton;
    private javax.swing.JPanel controlPanel;
    private javax.swing.JTable conversationTable;
    private javax.swing.JTextArea crlfTextArea;
    private javax.swing.JButton editButton;
    private javax.swing.JDialog editDialog;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollBar jScrollBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JButton loadButton;
    private javax.swing.JButton okButton;
    private javax.swing.JTable suspectedTable;
    private javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JTextArea xssTextArea;
    // End of variables declaration//GEN-END:variables
    
}
