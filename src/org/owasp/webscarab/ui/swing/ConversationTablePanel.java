/*
 * ConversationTablePanel.java
 *
 * Created on May 13, 2004, 12:20 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.util.ConversationFilter;
import org.owasp.webscarab.util.ConversationCriteria;
import org.owasp.webscarab.util.swing.ListFilter;
import org.owasp.webscarab.util.swing.TableSorter;
import org.owasp.webscarab.util.swing.ListTableModelAdaptor;
import org.owasp.webscarab.util.swing.TableRow;

import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.ListModel;
import javax.swing.table.TableModel;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;

import javax.swing.Action;
import javax.swing.AbstractAction;

import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import java.util.ArrayList;

/**
 *
 * @author  knoppix
 */
public class ConversationTablePanel extends javax.swing.JPanel {
    
    private SiteModel _siteModel;
    private ConversationFilter _conversationFilter;
    private ListFilter _conversationList;
    
    private ArrayList _conversationActions = new ArrayList();
    
    /** Creates new form ConversationTablePanel */
    public ConversationTablePanel(SiteModel siteModel) {
        _siteModel = siteModel;
        initComponents();
        
        initTable();
        addTableListeners();
        addTableActions();
    }
    
    private void initTable() {
        _conversationFilter = new ConversationFilter(_siteModel, null);
        ListModel clm = _siteModel.getConversationListModel();
        _conversationList = new ListFilter(clm, _conversationFilter);
        TableModel ctm = new ListTableModelAdaptor(_conversationList, new ConversationRow());
        TableSorter ts = new TableSorter(ctm, conversationTable.getTableHeader());
        conversationTable.setModel(ts);
        
        int[] preferredColumnWidths = {
            40, 60, 60, 300, 200, 200,
            80, 150, 80, 50, 100, 100
        };
        
        javax.swing.table.TableColumnModel columnModel = conversationTable.getColumnModel();
        for (int i=0; i<Math.min(preferredColumnWidths.length, columnModel.getColumnCount()); i++) {
            columnModel.getColumn(i).setPreferredWidth(preferredColumnWidths[i]);
        }
    }
    
    public void setFilterCriteria(ConversationCriteria criteria) {
        setFilterCriteria(new ConversationCriteria[] {criteria});
    }
    
    public void setFilterCriteria(ConversationCriteria[] criteria) {
        _conversationFilter.setCriteria(criteria);
    }
    
    private void addTableListeners() {
        // conversationTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // This listener updates the registered actions with the selected Conversation
        conversationTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) return;
                tableSelectionChanged();
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
    
    private void tableSelectionChanged() {
        int row = conversationTable.getSelectedRow();
        TableModel tm = conversationTable.getModel();
        Conversation c = null;
        if (row >-1) {
            String id = tm.getValueAt(row, 0).toString(); // UGLY hack! FIXME!!!!
            c = _siteModel.getConversation(id);
        }
        synchronized (_conversationActions) {
            for (int i=0; i<_conversationActions.size(); i++) {
                Action action = (Action) _conversationActions.get(i);
                action.putValue("TARGET", c);
            }
        }
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
        for (int i=0; i<actions.length; i++) {
            _conversationActions.add(actions[i]);
        }
        for (int i=0; i<actions.length; i++) {
            conversationPopupMenu.add(new JMenuItem(actions[i]));
        }
    }
    
    private void showSelectedConversation() {
        int row = conversationTable.getSelectedRow();
        TableModel tm = conversationTable.getModel();
        if (row >= 0) {
            String id = tm.getValueAt(row, 0).toString();
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
        JFrame frame = FrameCache.getFrame("Conversation " + id);
        if (frame == null) {
            ConversationPanel cp = new ConversationPanel();
            cp.setRequest(request, false);
            cp.setResponse(response, false);
            frame = cp.inFrame("Conversation " + id);
            frame.addWindowListener(new java.awt.event.WindowAdapter() {
                public void windowClosing(java.awt.event.WindowEvent evt) {
                    FrameCache.removeFrame("Conversation " + id);
                }
            });
            FrameCache.addFrame("Conversation " + id, frame);
        }
        frame.show();
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        conversationPopupMenu = new javax.swing.JPopupMenu();
        jScrollPane1 = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();

        conversationPopupMenu.setLabel("Conversation Actions");

        setLayout(new java.awt.BorderLayout());

        conversationTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane1.setViewportView(conversationTable);

        add(jScrollPane1, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPopupMenu conversationPopupMenu;
    private javax.swing.JTable conversationTable;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
    
    private class ConversationRow implements TableRow {
        
        private final String[] _columnNames = new String[] {
            "ID", "Date", "Method", "Url", "Query",
            "Cookie", "Status",
            "Set-Cookie", "Checksum", "Size",
            "Origin", "Comment"
        };
        
        public Class getColumnClass(int column) {
            if (_columnNames[column].equalsIgnoreCase("id") ||
            _columnNames[column].equalsIgnoreCase("size")) {
                return Integer.class;
            }
            return String.class;
        }
        
        public int getColumnCount() {
            return _columnNames.length;
        }
        
        public String getColumnName(int column) {
            if (column < _columnNames.length) {
                return _columnNames[column];
            }
            return "";
        }
        
        public Object getValueAt(Object object, int column) {
            if (! (object instanceof Conversation)) {
                return null; // throw ClassCastException?
            }
            Conversation c = (Conversation) object;
            if (column <= _columnNames.length) {
                String prop = _columnNames[column].toUpperCase();
                String value = c.getProperty(prop);
                if (prop.equals("ID") || prop.equals("SIZE")) {
                    try {
                        return new Integer(value);
                    } catch (NumberFormatException nfe) {
                        return value;
                    }
                }
                return value;
            } else {
                System.err.println("Attempt to get column " + column + " : column does not exist!");
                return null;
            }
        }
        
        public boolean isFieldEditable(Object object, int column) {
            return _columnNames[column].equalsIgnoreCase("Comment");
        }
        
        public void setValueAt(Object aValue, Object object, int column) {
            if (_columnNames[column].equalsIgnoreCase("Comment")) {
                Conversation c = (Conversation) object;
                c.setProperty(_columnNames[column].toUpperCase(), aValue.toString());
            }
        }
        
    }

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
                if (value != null) {
                    if (value instanceof Conversation) {
                        Conversation c = (Conversation) value;
                        if (c.getProperty(_type) != null) {
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
