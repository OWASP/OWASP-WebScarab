/*
 * SummaryPanel.java
 *
 * Created on December 16, 2003, 10:35 AM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.ui.Framework;
import org.owasp.webscarab.model.URLTreeModel;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.URLInfo;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.util.ConversationCriteria;
import org.owasp.webscarab.util.swing.JTreeTable;
import org.owasp.webscarab.util.swing.ListFilter;
import org.owasp.webscarab.util.swing.ListTableModelAdaptor;
import org.owasp.webscarab.util.swing.TableRow;
import org.owasp.webscarab.util.swing.TableSorter;

import javax.swing.JTree;
import javax.swing.ListModel;
import javax.swing.table.TableModel;

import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeSelectionModel;
import javax.swing.tree.TreePath;
import javax.swing.event.TreeSelectionListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.ListSelectionModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.Action;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;
import javax.swing.JMenuItem;

import java.util.ArrayList;

import java.net.URL;
import java.net.MalformedURLException;

/**
 *
 * @author  rdawes
 */
public class SummaryPanel extends javax.swing.JPanel {
    
    private Framework _framework;
    private JTreeTable _urlTreeTable;
    private SiteModel _siteModel;
    private ArrayList _urlActions = new ArrayList();
    private String _treeURL = null;
    
    private ConversationTablePanel _conversationTablePanel;
    
    /** Creates new form SummaryPanel */
    public SummaryPanel(Framework framework) {
        _framework = framework;
        _siteModel = framework.getSiteModel();
        
        initComponents();
        
        initTree();
        addTreeListeners();
        addTreeActions();
        
        _conversationTablePanel = new ConversationTablePanel(_siteModel);
        _conversationTablePanel.setFilterCriteria(new ConversationCriteria("OR", "Request URL", "not equals", ""));
        summarySplitPane.setRightComponent(_conversationTablePanel);
    }
    
    private void initTree() {
        _urlTreeTable = new JTreeTable(new SiteInfoModel(_framework.getSiteModel()));
        treeTableScrollPane.setViewportView(_urlTreeTable);
        
        JTree urlTree = _urlTreeTable.getTree();
        urlTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        urlTree.setRootVisible(false);
        urlTree.setShowsRootHandles(true);
        
        int[] preferredColumnWidths = {
            400, 80, 80, 50, 30, 30, 30
        };
        
        javax.swing.table.TableColumnModel columnModel = _urlTreeTable.getColumnModel();
        for (int i=0; i<Math.min(preferredColumnWidths.length, columnModel.getColumnCount()); i++) {
            columnModel.getColumn(i).setPreferredWidth(preferredColumnWidths[i]);
        }
    }
    
    private void addTreeListeners() {
        // Listen for when the selection changes.
        // We use this to set the selected URLInfo for each action, and eventually
        // to filter the conversation list
        final JTree urlTree = _urlTreeTable.getTree();
        urlTree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(TreeSelectionEvent e) {
                TreePath selection = urlTree.getSelectionPath();
                URLInfo u = null;
                if (selection != null) {
                    Object o = selection.getLastPathComponent();
                    if (o instanceof URLTreeModel.URLNode) {
                        URLTreeModel.URLNode un = (URLTreeModel.URLNode) o;
                        _treeURL = un.getURL();
                        try {
                            u = _siteModel.getURLInfo(new URL(_treeURL));
                        } catch (MalformedURLException mue) {
                            System.err.println("Malformed URL " + _treeURL + " : " + mue);
                        }
                    }
                } else {
                    _treeURL = null;
                }
                if (treeCheckBox.isSelected()) {
                    ConversationCriteria fc = new ConversationCriteria("OR", "Request URL", "equals", _treeURL);
                    _conversationTablePanel.setFilterCriteria(fc);
                }
                synchronized (_urlActions) {
                    for (int i=0; i<_urlActions.size(); i++) {
                        AbstractAction action = (AbstractAction) _urlActions.get(i);
                        action.putValue("TARGET", u);
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
                if (e.isPopupTrigger()) {
                    urlPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }
    
    private void addTreeActions() {
        Action[] actions = new Action[] {
            new FragmentAction("COMMENTS"),
            new FragmentAction("SCRIPTS"),
        };
        addURLActions(actions);
    }
    
    public void addURLActions(Action[] actions) {
        if (actions == null) return;
        synchronized (_urlActions) {
            for (int i=0; i<actions.length; i++) {
                _urlActions.add(actions[i]);
            }
        }
        synchronized (urlPopupMenu) {
            for (int i=0; i<actions.length; i++) {
                urlPopupMenu.add(new JMenuItem(actions[i]));
            }
        }
    }
    
    public void addConversationActions(Action[] actions) {
        _conversationTablePanel.addConversationActions(actions);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        urlPopupMenu = new javax.swing.JPopupMenu();
        summarySplitPane = new javax.swing.JSplitPane();
        urlPanel = new javax.swing.JPanel();
        treeCheckBox = new javax.swing.JCheckBox();
        treeTableScrollPane = new javax.swing.JScrollPane();

        urlPopupMenu.setLabel("URL Actions");

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
        urlPanel.add(treeTableScrollPane, gridBagConstraints);

        summarySplitPane.setLeftComponent(urlPanel);

        add(summarySplitPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    private void treeCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_treeCheckBoxActionPerformed
        if (treeCheckBox.isSelected() && _treeURL != null) {
            ConversationCriteria fc = new ConversationCriteria("OR", "Request URL", "equals", _treeURL);
            _conversationTablePanel.setFilterCriteria(fc);
        } else {
            ConversationCriteria fc = new ConversationCriteria("OR", "Request URL", "not equals", "");
            _conversationTablePanel.setFilterCriteria(fc);
        }
    }//GEN-LAST:event_treeCheckBoxActionPerformed
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JSplitPane summarySplitPane;
    private javax.swing.JCheckBox treeCheckBox;
    private javax.swing.JScrollPane treeTableScrollPane;
    private javax.swing.JPanel urlPanel;
    private javax.swing.JPopupMenu urlPopupMenu;
    // End of variables declaration//GEN-END:variables
    
    private class FragmentAction extends AbstractAction {
        private String _type;
        public FragmentAction(String type) {
            _type = type;
            putValue(Action.NAME, "Show " + _type.toLowerCase());
            putValue(Action.SHORT_DESCRIPTION, "Show " + _type.toLowerCase());
            putValue("TARGET", null);
        }
        
        public void actionPerformed(ActionEvent e) {
            Object o = getValue("TARGET");
            if (o == null) return;
            String[] checksums = null;
            String title = "";
            if (o != null && o instanceof URLInfo) {
                URLInfo u = (URLInfo) o;
                checksums = u.getPropertyAsArray(_type);
                title = "URL " + u.getURL() + " " + _type.toLowerCase();
            }
            if (checksums != null) {
                FragmentsFrame ff = (FragmentsFrame) FrameCache.getFrame(title);
                if (ff == null) {
                    ff = new FragmentsFrame(_siteModel);
                    ff.setTitle(title);
                    ff.loadFragments(checksums);
                    FrameCache.addFrame(title, ff);
                    final String key = title;
                    ff.addWindowListener(new java.awt.event.WindowAdapter() {
                        public void windowClosing(java.awt.event.WindowEvent evt) {
                            FrameCache.removeFrame(key);
                        }
                    });
                }
                ff.show();
            }
        }
        
        public void putValue(String key, Object value) {
            super.putValue(key, value);
            if (key != null && key.equals("TARGET")) {
                if (value != null && value instanceof URLInfo) {
                    URLInfo u = (URLInfo) value;
                    if (u.getProperty(_type) != null) {
                        setEnabled(true);
                        return;
                    }
                }
                setEnabled(false);
            }
        }
    }
    
}
