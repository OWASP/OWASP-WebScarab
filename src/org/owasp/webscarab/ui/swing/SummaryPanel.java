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

import javax.swing.JTree;

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

import java.util.TreeMap;
import java.util.ArrayList;

import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.SiteModel;

import java.net.URL;
import java.net.MalformedURLException;

/**
 *
 * @author  rdawes
 */
public class SummaryPanel extends javax.swing.JPanel {
    
    private Framework _framework;
    private JTreeTable _urlTreeTable;
    private ConversationTableModel _ctm;
    private SiteModel _siteModel;
    private TreeMap _windowCache = new TreeMap();
    private ArrayList _conversationActions = new ArrayList();
    private ArrayList _urlActions = new ArrayList();
    private ConversationListFilter _listFilter;
    private String _treeURL = null;
    
    /** Creates new form SummaryPanel */
    public SummaryPanel(Framework framework) {
        _framework = framework;
        _siteModel = framework.getSiteModel();
        
        initComponents();
        
        initTree();
        addTreeListeners();
        addTreeActions();
        
        initTable();
        addTableListeners();
        addTableActions();
        
    }
    
    private void initTree() {
        _urlTreeTable = new JTreeTable(new SiteInfoModel(_framework.getSiteModel()));
        treeTableScrollPane.setViewportView(_urlTreeTable);
        
        JTree urlTree = _urlTreeTable.getTree();
        urlTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        urlTree.setRootVisible(false);
        urlTree.setShowsRootHandles(true);
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
                    _listFilter.setURL(_treeURL);
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
    
    private void initTable() {
        _listFilter = new ConversationListFilter(_siteModel.getConversationListModel());
        _ctm = new ConversationTableModel(_listFilter);
        conversationTable.setModel(_ctm);
        
        javax.swing.table.TableColumnModel columnModel = conversationTable.getColumnModel();
        for (int i=0; i<_ctm.getColumnCount(); i++) {
            columnModel.getColumn(i).setPreferredWidth(_ctm.getPreferredColumnWidth(i));
        }
    }
    
    private void addTableListeners() {
        // conversationTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // This listener updates the registered actions with the selected Conversation
        conversationTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) return;
                int row = conversationTable.getSelectedRow();
                Conversation c = null;
                if (row >-1) {
                    String id = (String) _ctm.getValueAt(row, 0);
                    c = _siteModel.getConversation(id);
                }
                synchronized (_conversationActions) {
                    for (int i=0; i<_conversationActions.size(); i++) {
                        AbstractAction action = (AbstractAction) _conversationActions.get(i);
                        action.putValue("TARGET", c);
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
                if (e.isPopupTrigger()) {
                    conversationPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == e.BUTTON1) {
                    showSelectedConversation();
                }
            }
        });
        
    }
    
    private void addTableActions() {
        Action[] actions = new Action[] {
            new ShowDetailAction(),
            new FragmentAction("COMMENTS"),
            new FragmentAction("SCRIPTS"),
        };
        addConversationActions(actions);
    }
    
    public void addConversationActions(Action[] actions) {
        if (actions == null) return;
        synchronized (_conversationActions) {
            for (int i=0; i<actions.length; i++) {
                _conversationActions.add(actions[i]);
            }
        }
        synchronized (conversationPopupMenu) {
            for (int i=0; i< actions.length; i++) {
                conversationPopupMenu.add(new JMenuItem(actions[i]));
            }
        }
    }
    
    private void showSelectedConversation() {
        int row = conversationTable.getSelectedRow();
        if (row >= 0) {
            String id = (String) _ctm.getValueAt(row, 0);
            showConversationDetails(id);
        }
    }
    
    private void showConversationDetails(final String id) {
        Request request = _siteModel.getRequest(id);
        Response response = _siteModel.getResponse(id);
        if (request == null && response == null) {
            JOptionPane.showMessageDialog(null, "Conversation " + id + " was not saved! Please start a new session first!", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        synchronized (_windowCache) {
            ConversationPanel cp = (ConversationPanel) _windowCache.get("Conversation " + id);
            if (cp == null) {
                cp = new ConversationPanel();
                _windowCache.put("Conversation " + id, cp);
                cp.setRequest(request, false);
                cp.setResponse(response, false);
            }
            JFrame frame = cp.inFrame("Conversation " + id);
            frame.addWindowListener(new java.awt.event.WindowAdapter() {
                public void windowClosing(java.awt.event.WindowEvent evt) {
                    synchronized (_windowCache) {
                        _windowCache.remove("Conversation " + id);
                    }
                }
            });
            frame.show();
        }
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
        jSplitPane1 = new javax.swing.JSplitPane();
        urlPanel = new javax.swing.JPanel();
        treeCheckBox = new javax.swing.JCheckBox();
        treeTableScrollPane = new javax.swing.JScrollPane();
        conversationPanel = new javax.swing.JPanel();
        conversationTableScrollPane = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();

        urlPopupMenu.setLabel("URL Actions");
        conversationPopupMenu.setLabel("Conversation Actions");

        setLayout(new java.awt.BorderLayout());

        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setResizeWeight(0.5);
        jSplitPane1.setOneTouchExpandable(true);
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

        jSplitPane1.setLeftComponent(urlPanel);

        conversationPanel.setLayout(new java.awt.GridBagLayout());

        conversationPanel.setMinimumSize(new java.awt.Dimension(22, 100));
        conversationPanel.setPreferredSize(new java.awt.Dimension(3, 100));
        conversationTableScrollPane.setMinimumSize(null);
        conversationTableScrollPane.setPreferredSize(null);
        conversationTableScrollPane.setAutoscrolls(true);
        conversationTable.setBorder(new javax.swing.border.BevelBorder(javax.swing.border.BevelBorder.RAISED));
        conversationTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        conversationTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        conversationTable.setMaximumSize(new java.awt.Dimension(2147483647, 32767));
        conversationTable.setMinimumSize(null);
        conversationTable.setPreferredScrollableViewportSize(null);
        conversationTable.setPreferredSize(null);
        conversationTable.setOpaque(false);
        conversationTableScrollPane.setViewportView(conversationTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        conversationPanel.add(conversationTableScrollPane, gridBagConstraints);

        jSplitPane1.setRightComponent(conversationPanel);

        add(jSplitPane1, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents

    private void treeCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_treeCheckBoxActionPerformed
        if (treeCheckBox.isSelected() && _treeURL != null) {
            _listFilter.setURL(_treeURL);
        } else {
            _listFilter.setURL(null);
        }
    }//GEN-LAST:event_treeCheckBoxActionPerformed
      
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel conversationPanel;
    private javax.swing.JPopupMenu conversationPopupMenu;
    private javax.swing.JTable conversationTable;
    private javax.swing.JScrollPane conversationTableScrollPane;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JCheckBox treeCheckBox;
    private javax.swing.JScrollPane treeTableScrollPane;
    private javax.swing.JPanel urlPanel;
    private javax.swing.JPopupMenu urlPopupMenu;
    // End of variables declaration//GEN-END:variables
    
    private class ShowDetailAction extends AbstractAction {
        public ShowDetailAction() {
            putValue(Action.NAME, "Show details");
            putValue(Action.SHORT_DESCRIPTION, "Opens a new window showing the request and response");
            putValue("TARGET", null);
        }
        
        public void actionPerformed(ActionEvent e) {
            Object o = getValue("TARGET");
            if (o != null && o instanceof Conversation) {
                Conversation c = (Conversation) o;
                String id = c.getProperty("ID");
                if (id != null) {
                    showConversationDetails(id);
                } else {
                    System.err.println("ID was null!");
                }
            }
        }
        
        public void putValue(String key, Object value) {
            super.putValue(key, value);
            if (key != null && key.equals("TARGET")) {
                Conversation c = (Conversation) value;
                if (c == null) {
                    setEnabled(false);
                } else {
                    setEnabled(true);
                }
            }
        }
    }
    
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
            if (o instanceof Conversation) {
                Conversation c = (Conversation) o;
                checksums = c.getPropertyAsArray(_type);
                title = "Conversation " + c.getProperty("ID") + " " + _type.toLowerCase();
            }
            if (o != null && o instanceof URLInfo) {
                URLInfo u = (URLInfo) o;
                checksums = u.getPropertyAsArray(_type);
                title = "URL " + u.getURL() + " " + _type.toLowerCase();
            }
            if (checksums != null) {
                synchronized (_windowCache) {
                    FragmentsFrame ff = (FragmentsFrame) _windowCache.get(title);
                    if (ff == null) {
                        ff = new FragmentsFrame(_siteModel);
                        ff.setTitle(title);
                        ff.loadFragments(checksums);
                        _windowCache.put(title, ff);
                    }
                    final String key = title;
                    ff.addWindowListener(new java.awt.event.WindowAdapter() {
                        public void windowClosing(java.awt.event.WindowEvent evt) {
                            synchronized (_windowCache) {
                                _windowCache.remove(key);
                            }
                        }
                    });
                    ff.show();
                }
            } else {
                System.err.println("No checksums to display");
            }
        }
        
        public void putValue(String key, Object value) {
            super.putValue(key, value);
            if (key != null && key.equals("TARGET")) {
                if (value != null) {
                    if (value instanceof Conversation) {
                        Conversation c = (Conversation) value;
                        if (c.getProperty(_type) != null) {
                            setEnabled(true);
                            return;
                        }
                    } else if (value instanceof URLInfo) {
                        URLInfo u = (URLInfo) value;
                        if (u.getProperty(_type) != null) {
                            setEnabled(true);
                            return;
                        }
                    }
                }
                setEnabled(false);
            }
        }
    }
    
}
