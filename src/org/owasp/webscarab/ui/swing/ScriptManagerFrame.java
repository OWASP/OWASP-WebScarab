/*
 * ScriptManagerFrame.java
 *
 * Created on 09 January 2005, 09:06
 */

package org.owasp.webscarab.ui.swing;

import org.apache.bsf.BSFException;

import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Script;
import org.owasp.webscarab.plugin.ScriptListener;
import org.owasp.webscarab.plugin.ScriptManager;

import org.owasp.webscarab.util.swing.JTreeTable;
import org.owasp.webscarab.util.swing.treetable.AbstractTreeTableModel;

import java.awt.Component;

import javax.swing.SwingUtilities;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.TreeSelectionModel;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreePath;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import java.io.File;
import java.io.IOException;

/**
 *
 * @author  rogan
 */
public class ScriptManagerFrame extends javax.swing.JFrame implements ScriptListener {
    
    private ScriptManager _manager;
    private Hook _hook = null;
    private Script _script = null;
    private JTreeTable _hookTree;
    private HookScriptTreeModel _treeModel = new HookScriptTreeModel();
    
    private File _dir = null;
    
    /** Creates new form ScriptManagerFrame */
    public ScriptManagerFrame(ScriptManager manager) {
        _manager = manager;
        initComponents();
        _hookTree = new JTreeTable(_treeModel);
        hookScrollPane.getViewport().add(_hookTree);
        _hookTree.setModel(_treeModel);
        final JTree hookTree = _hookTree.getTree();
        hookTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        hookTree.setRootVisible(false);
        hookTree.setShowsRootHandles(true);
        hookTree.setCellRenderer(new HookTreeRenderer());
        hookTree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(TreeSelectionEvent e) {
                TreePath selection = hookTree.getSelectionPath();
                if (selection != null) {
                    Object o = selection.getLastPathComponent();
                    if (o instanceof Hook) {
                        showHook((Hook)o);
                        showScript(null);
                    } else if (o instanceof Script) {
                        showHook((Hook)selection.getParentPath().getLastPathComponent());
                        showScript((Script) o);
                    }
                } else {
                    showHook(null);
                    showScript(null);
                }
            }
        });
        _manager.addScriptListener(this);
    }
    
    private void showHook(Hook hook) {
        _hook = hook;
        if (hook != null) {
            descriptionTextArea.setText(hook.getDescription());
            descriptionTextArea.setCaretPosition(0);
            addButton.setEnabled(true);
        } else {
            descriptionTextArea.setText("");
            addButton.setEnabled(false);
        }
    }
    
    private void showScript(Script script) {
        _script = script;
        if (script == null) {
            scriptTextField.setText("");
            scriptTextArea.setText("");
            removeButton.setEnabled(false);
        } else {
            scriptTextField.setText(script.getFile().getAbsolutePath());
            scriptTextArea.setText(script.getScript());
            scriptTextArea.setCaretPosition(0);
            removeButton.setEnabled(true);
        }
        saveButton.setEnabled(false);
    }
    
    public void hooksChanged() {
        _treeModel.fireStructureChanged();
    }
    
    public void hookStarted(String plugin, Hook hook) {
        //             firePathChanged(new TreePath(new Object[] {plugin, hook}));
    }
    
    public void scriptStarted(String plugin, Hook hook, Script script) {
        //             firePathChanged(new TreePath(new Object[] {plugin, hook, script}));
    }
    
    public void scriptChanged(final String plugin, final Hook hook, final Script script) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                _treeModel.firePathChanged(new TreePath(new Object[] {_treeModel.getRoot(), plugin, hook, script}));
            }
        });
    }
    
    public void scriptEnded(String plugin, Hook hook, Script script) {
        //             firePathChanged(new TreePath(new Object[] {plugin, hook, script}));
    }
    
    public void hookEnded(String plugin, Hook hook) {
        //             firePathChanged(new TreePath(new Object[] {plugin, hook}));
    }
    
    public void scriptError(final String plugin, final Hook hook, final Script script, final Throwable error) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                JOptionPane.showMessageDialog(null, new String[] {"Error running script : ", plugin + hook.getName(), script.getFile().getName(), error.getMessage()}, "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }
    
    public void scriptAdded(String plugin, Hook hook, Script script) {
        _treeModel.fireTreeStructureChanged(new TreePath(new Object[] {_treeModel.getRoot(), plugin, hook}));
    }
    
    public void scriptRemoved(String plugin, Hook hook, Script script) {
        _treeModel.fireTreeStructureChanged(new TreePath(new Object[] {_treeModel.getRoot(), plugin, hook}));
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        jPanel2 = new javax.swing.JPanel();
        hookScrollPane = new javax.swing.JScrollPane();
        jLabel3 = new javax.swing.JLabel();
        descriptionTextArea = new javax.swing.JTextArea();
        jLabel2 = new javax.swing.JLabel();
        scriptTextField = new javax.swing.JTextField();
        jScrollPane3 = new javax.swing.JScrollPane();
        scriptTextArea = new javax.swing.JTextArea();
        scriptToolBar = new javax.swing.JToolBar();
        newButton = new javax.swing.JButton();
        addButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        saveButton = new javax.swing.JButton();
        saveAsButton = new javax.swing.JButton();

        setTitle("Scripted Events");
        jPanel2.setLayout(new java.awt.GridBagLayout());

        hookScrollPane.setMaximumSize(new java.awt.Dimension(300, 32767));
        hookScrollPane.setMinimumSize(new java.awt.Dimension(300, 200));
        hookScrollPane.setPreferredSize(new java.awt.Dimension(300, 363));
        hookScrollPane.setVerifyInputWhenFocusTarget(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridheight = 3;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel2.add(hookScrollPane, gridBagConstraints);

        jLabel3.setText("Hook description : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        jPanel2.add(jLabel3, gridBagConstraints);

        descriptionTextArea.setBackground(new java.awt.Color(204, 204, 204));
        descriptionTextArea.setEditable(false);
        descriptionTextArea.setLineWrap(true);
        descriptionTextArea.setWrapStyleWord(true);
        descriptionTextArea.setBorder(null);
        descriptionTextArea.setMinimumSize(new java.awt.Dimension(200, 45));
        descriptionTextArea.setPreferredSize(new java.awt.Dimension(400, 45));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.weightx = 1.0;
        jPanel2.add(descriptionTextArea, gridBagConstraints);

        jLabel2.setText("Script : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 0, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        jPanel2.add(jLabel2, gridBagConstraints);

        scriptTextField.setBackground(new java.awt.Color(204, 204, 204));
        scriptTextField.setEditable(false);
        scriptTextField.setBorder(null);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 0, 4);
        jPanel2.add(scriptTextField, gridBagConstraints);

        jScrollPane3.setPreferredSize(new java.awt.Dimension(200, 200));
        jScrollPane3.setViewportView(scriptTextArea);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel2.add(jScrollPane3, gridBagConstraints);

        getContentPane().add(jPanel2, java.awt.BorderLayout.CENTER);

        newButton.setText("New");
        newButton.setEnabled(false);
        scriptToolBar.add(newButton);

        addButton.setText("Add");
        addButton.setEnabled(false);
        addButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addButtonActionPerformed(evt);
            }
        });

        scriptToolBar.add(addButton);

        removeButton.setText("Remove");
        removeButton.setEnabled(false);
        removeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeButtonActionPerformed(evt);
            }
        });

        scriptToolBar.add(removeButton);

        saveButton.setText("Save");
        saveButton.setEnabled(false);
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });

        scriptToolBar.add(saveButton);

        saveAsButton.setText("Save As");
        saveAsButton.setEnabled(false);
        scriptToolBar.add(saveAsButton);

        getContentPane().add(scriptToolBar, java.awt.BorderLayout.NORTH);

        pack();
    }//GEN-END:initComponents
    
    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_saveButtonActionPerformed
        
    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeButtonActionPerformed
        TreePath path = _hookTree.getTree().getSelectionPath();
        if (path.getPathCount()==4) {
            String plugin = (String) path.getPathComponent(1);
            Hook hook = (Hook) path.getPathComponent(2);
            Script script = (Script) path.getPathComponent(3);
            _manager.removeScript(plugin, hook, script);
        }
    }//GEN-LAST:event_removeButtonActionPerformed
    
    private void addButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addButtonActionPerformed
        TreePath path = _hookTree.getTree().getSelectionPath();
        String plugin = null;
        Hook hook = null;
        if (path.getPathCount()>=3) {
            plugin = (String) path.getPathComponent(1);
            hook = (Hook) path.getPathComponent(2);
        } else {
            return;
        }
        JFileChooser jfc = new JFileChooser(_dir);
        jfc.setDialogTitle("Load script");
        int returnVal = jfc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = jfc.getSelectedFile();
            try {
                Script script = new Script(file);
                _manager.addScript(plugin, hook, script);
            } catch (IOException ioe) {
                JOptionPane.showMessageDialog(null, new String[] {"Error loading Script : ", ioe.getMessage()}, "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }//GEN-LAST:event_addButtonActionPerformed
    
    /** Exit the Application */
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addButton;
    private javax.swing.JTextArea descriptionTextArea;
    private javax.swing.JScrollPane hookScrollPane;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JButton newButton;
    private javax.swing.JButton removeButton;
    private javax.swing.JButton saveAsButton;
    private javax.swing.JButton saveButton;
    private javax.swing.JTextArea scriptTextArea;
    private javax.swing.JTextField scriptTextField;
    private javax.swing.JToolBar scriptToolBar;
    // End of variables declaration//GEN-END:variables
    
    private class HookScriptTreeModel extends AbstractTreeTableModel {
        
        Object _root = new String("RooT");
        
        public Class getColumnClass(int column) {
            if (column == 0) return super.getColumnClass(column);
            return Boolean.class;
        }
        
        public int getColumnCount() {
            return 2;
        }
        
        public String getColumnName(int i) {
            if (i == 1) return "Enabled";
            return "";
        }
        
        public Object getValueAt(Object node, int column) {
            if (column == 0) return node;
            if (node instanceof Script) {
                Script script = (Script) node;
                return new Boolean(script.isEnabled());
            }
            return null;
        }
        
        public Object getChild(Object parent, int index) {
            if (parent == _root) {
                return _manager.getPlugin(index);
            } else if (parent instanceof String) {
                return _manager.getHook((String) parent, index);
            } else if (parent instanceof Hook) {
                return ((Hook) parent).getScript(index);
            } else return null;
        }
        
        public int getChildCount(Object parent) {
            if (parent == _root) {
                return _manager.getPluginCount();
            } else if (parent instanceof String) {
                return _manager.getHookCount((String) parent);
            } else if (parent instanceof Hook) {
                return ((Hook) parent).getScriptCount();
            } else return 0;
        }
        
        public Object getRoot() {
            return _root;
        }
        
        public boolean isLeaf(Object node) {
            if (node instanceof Script) return true;
            return false;
        }
        
        public void valueForPathChanged(javax.swing.tree.TreePath path, Object newValue) {
        }
        
        public void fireStructureChanged() {
            super.fireStructureChanged();
        }
        
        public void fireTreeStructureChanged(TreePath path) {
            super.fireTreeStructureChanged(path);
        }
        
        public void firePathChanged(TreePath path) {
            super.firePathChanged(path);
        }
        
        public void setValueAt(Object aValue, Object node, int column) {
            if (column == 1 && node instanceof Script) {
                ((Script) node).setEnabled(aValue == Boolean.TRUE);
            } else super.setValueAt(aValue, node, column);
        }
        
        public boolean isCellEditable(Object node, int column) {
            if (node instanceof Script && column == 1) return true;
            return super.isCellEditable(node, column);
        }
        
    }
    
    private class HookTreeRenderer extends DefaultTreeCellRenderer {
        
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            Component comp = super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
            if (value instanceof Hook && comp instanceof JLabel) {
                JLabel label = (JLabel) comp;
                Hook hook = (Hook) value;
                if (hook != null) {
                    label.setText(hook.getName());
                }
            } else if (value instanceof Script && comp instanceof JLabel) {
                JLabel label = (JLabel) comp;
                Script script = (Script) value;
                if (script != null) {
                    label.setText(script.getFile().getName());
                }
            }
            return comp;
        }
        
    }
    
}
