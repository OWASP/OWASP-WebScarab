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
 * FragmentsPanel.java
 *
 * Created on 09 December 2004, 10:37
 */

package org.owasp.webscarab.plugin.fragments.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.SiteModelAdapter;

import org.owasp.webscarab.plugin.fragments.Fragments;
import org.owasp.webscarab.plugin.fragments.FragmentsUI;

import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.ui.swing.ConversationListTableModel;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.MultiLineCellRenderer;
import org.owasp.webscarab.util.swing.ListComboBoxModel;

import javax.swing.JPanel;
import javax.swing.Action;
import javax.swing.AbstractAction;
import javax.swing.DefaultListModel;
import javax.swing.SwingUtilities;
import javax.swing.ListSelectionModel;
import javax.swing.JList;

import java.awt.Component;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;

import javax.swing.AbstractListModel;

/**
 *
 * @author  rogan
 */
public class FragmentsPanel extends javax.swing.JPanel implements SwingPluginUI, FragmentsUI {
    
    private Fragments _fragments;
    private Logger _logger = Logger.getLogger(getClass().getName());
    private SiteModel _model = null;
    
    private String _type = null;
    
    private Action[] _conversationActions;
    private Action[] _urlActions;
    private Map _conversationColumns = new HashMap();
    private Map _urlColumns = new HashMap();
    
    private DefaultListModel _typeListModel = new DefaultListModel();
    private FragmentListModel _flm = new FragmentListModel();
    private DefaultListModel _conversationList = new DefaultListModel();
    
    private Listener _listener = new Listener();
    
    
    private static final ColumnDataModel[] CDM = new ColumnDataModel[0];
    
    /** Creates new form FragmentsPanel */
    public FragmentsPanel(Fragments fragments) {
        initComponents();
        _model = fragments.getModel();
        
        fragmentList.setCellRenderer(new FragmentRenderer());
        fragmentList.setModel(_flm);
        fragmentList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        _typeListModel.addElement("COMMENTS");
        _typeListModel.addElement("SCRIPTS");
        typeComboBox.setModel(new ListComboBoxModel(_typeListModel));
        typeComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                _type = (String) typeComboBox.getSelectedItem();
                _flm.setFilter(null, _type);
            }
        });
        
        fragmentList.addListSelectionListener(new FragmentsListListener());
        conversationTable.setModel(new ConversationListTableModel(_model,_conversationList));
        
        _fragments = fragments;
        createActions();
        
        _model.addModelListener(_listener);
        _fragments.setUI(this);
        
    }
    
    private void createActions() {
        _conversationActions = new Action[] {
            new FragmentsAction("CONVERSATION", "SCRIPTS"),
            new FragmentsAction("CONVERSATION","COMMENTS")
        };
        _urlActions = new Action[] {
            new FragmentsAction("URL", "SCRIPTS"),
            new FragmentsAction("URL","COMMENTS")
        };
        ColumnDataModel cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                String value = _model.getConversationProperty((ConversationID) key, "COMMENTS");
                return Boolean.valueOf(value != null);
            }
            public String getColumnName() { return "Comments"; }
            public Class getColumnClass() { return Boolean.class; }
        };
        _conversationColumns.put("COMMENTS", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                String value = _model.getConversationProperty((ConversationID) key, "SCRIPTS");
                return Boolean.valueOf(value != null);
            }
            public String getColumnName() { return "Scripts"; }
            public Class getColumnClass() { return Boolean.class; }
        };
        _conversationColumns.put("SCRIPTS", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getConversationProperty((ConversationID) key, "COOKIE");
            }
            public String getColumnName() { return "Cookie"; }
            public Class getColumnClass() { return String.class; }
        };
        _conversationColumns.put("COOKIE", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getConversationProperty((ConversationID) key, "SET-COOKIE");
            }
            public String getColumnName() { return "Set-Cookie"; }
            public Class getColumnClass() { return String.class; }
        };
        _conversationColumns.put("SET-COOKIE", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                String value = _model.getUrlProperty((HttpUrl) key, "COMMENTS");
                return Boolean.valueOf(value != null);
            }
            public String getColumnName() { return "Comments"; }
            public Class getColumnClass() { return Boolean.class; }
        };
        _urlColumns.put("COMMENTS", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                String value = _model.getUrlProperty((HttpUrl) key, "SCRIPTS");
                return Boolean.valueOf(value != null);
            }
            public String getColumnName() { return "Scripts"; }
            public Class getColumnClass() { return Boolean.class; }
        };
        _urlColumns.put("SCRIPTS", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                String value = _model.getUrlProperty((HttpUrl) key, "SET-COOKIE");
                return Boolean.valueOf(value != null);
            }
            public String getColumnName() { return "Set-Cookie"; }
            public Class getColumnClass() { return Boolean.class; }
        };
        _urlColumns.put("SET-COOKIE", cdm);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        jSplitPane1 = new javax.swing.JSplitPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        fragmentList = new javax.swing.JList();
        typeComboBox = new javax.swing.JComboBox();
        jScrollPane2 = new javax.swing.JScrollPane();
        conversationTable = new javax.swing.JTable();

        setLayout(new java.awt.BorderLayout());

        setPreferredSize(new java.awt.Dimension(602, 570));
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setResizeWeight(0.65);
        jSplitPane1.setOneTouchExpandable(true);
        jPanel1.setLayout(new java.awt.BorderLayout());

        jPanel1.setMinimumSize(new java.awt.Dimension(400, 300));
        jPanel1.setPreferredSize(new java.awt.Dimension(400, 300));
        jScrollPane1.setViewportView(fragmentList);

        jPanel1.add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jPanel1.add(typeComboBox, java.awt.BorderLayout.NORTH);

        jSplitPane1.setLeftComponent(jPanel1);

        jScrollPane2.setPreferredSize(new java.awt.Dimension(200, 200));
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
        jScrollPane2.setViewportView(conversationTable);

        jSplitPane1.setRightComponent(jScrollPane2);

        add(jSplitPane1, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    public Action[] getConversationActions() {
        return _conversationActions;
    }
    
    public void setEnabled(boolean enabled) {
        // FIXME we should do something here
    }
    
    public JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "Fragments";
    }
    
    public Action[] getUrlActions() {
        return _urlActions;
    }
    
    public ColumnDataModel[] getConversationColumns() {
        return (ColumnDataModel[]) _conversationColumns.values().toArray(CDM);
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return (ColumnDataModel[]) _urlColumns.values().toArray(CDM);
    }
    
    public void fragmentAdded(HttpUrl url, final ConversationID id, final String type, final String key) {
        // _logger.info(type + " added " + url + " key = " + key);
        try {
            SwingUtilities.invokeAndWait(new Runnable() {
                public void run() {
                    if (_type != null && _type.equals(type)) {
                        _flm.fragmentAdded(type, key);
                        // this does not work, because we fire only on the first occurence
                        // of the key! Doh! FIXME!
//                        Object selected = fragmentList.getSelectedValue();
//                        _logger.info("Selected is " + selected + " key is " + key);
//                        if (selected != null && selected.equals(key)) {
//                            _conversationList.addElement(id);
//                        }
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable conversationTable;
    private javax.swing.JList fragmentList;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JComboBox typeComboBox;
    // End of variables declaration//GEN-END:variables
    
    private class FragmentsAction extends AbstractAction {
        
        private String _type;
        private String _where;
        
        public FragmentsAction(String where, String type) {
            _where = where;
            _type = type;
            putValue(NAME, "Show " + _type.toLowerCase());
            putValue(SHORT_DESCRIPTION, "Displays any " + _type.toLowerCase() + " seen in the " + _where.toLowerCase());
            putValue(_where, null);
        }
        
        private String[] getFragments() {
            String[] fragments = new String[0];
            Object o = getValue(_where);
            if (_where.equals("URL") && o instanceof HttpUrl) {
                HttpUrl url = (HttpUrl) o;
                if (_type.equals("COMMENTS")) {
                    fragments = _fragments.getUrlComments(url);
                } else if (_type.equals("SCRIPTS")) {
                    fragments = _fragments.getUrlScripts(url);
                }
            } else if (_where.equals("CONVERSATION") && o instanceof ConversationID) {
                ConversationID id = (ConversationID) o;
                if (_type.equals("COMMENTS")) {
                    fragments = _fragments.getConversationComments(id);
                } else if (_type.equals("SCRIPTS")) {
                    fragments = _fragments.getConversationScripts(id);
                }
            }
            return fragments;
        }
        
        public void actionPerformed(java.awt.event.ActionEvent e) {
            String[] fragments = getFragments();
            if (fragments.length > 0) {
                FragmentsFrame ff = new FragmentsFrame();
                ff.setFragments(fragments);
                ff.setTitle(_type + " in " + _where + " " + getValue(_where));
                ff.show();
            }
        }
        
        public void putValue(String key, Object value) {
            super.putValue(key, value);
            if (key != null && key.equals(_where)) {
                if (value != null && getFragments().length > 0) {
                    setEnabled(true);
                } else {
                    setEnabled(false);
                }
            }
        }
        
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationChanged(ConversationID id, String property) {
            ColumnDataModel cdm = (ColumnDataModel) _conversationColumns.get(property);
            if (cdm != null) cdm.fireValueChanged(id);
        }
        
        public void urlChanged(HttpUrl url, String property) {
            ColumnDataModel cdm = (ColumnDataModel) _urlColumns.get(property);
            if (cdm != null) cdm.fireValueChanged(url);
        }
        
        public void dataChanged() {
            _flm.fireContentsChanged();
        }
    }
    
    private class FragmentListModel extends AbstractListModel {

        private String _type = null;
        private Object _id = null;
        private int _size = 0;

        public FragmentListModel() {
        }

        public void setFilter(Object id, String type) {
            fireIntervalRemoved(this, 0, getSize());
            _id = id;
            _type = type;
            fireIntervalAdded(this, 0, getSize());
        }

        public Object getElementAt(int index) {
            return _fragments.getFragmentKeyAt(_type, index);
        }

        public int getSize() {
            if (_type == null) return 0;
            _size = _fragments.getFragmentCount(_type);
            return _size;
        }

        public void fragmentAdded(String type, String key) {
            if (_type == null || !_type.equals(type)) return;
            int row = _fragments.indexOfFragment(type, key);
            fireIntervalAdded(this, row, row);
        }

        public void fireContentsChanged() {
            if (_size > 0) fireIntervalRemoved(this, 0, _size);
            if (getSize()>0) fireIntervalAdded(this, 0, getSize());
        }
    
    }
            
    private class FragmentRenderer extends MultiLineCellRenderer {
        
        public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            if (value instanceof String) {
                value = _fragments.getFragment((String) value);
            }
            return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        }
    
    }
    
    private class FragmentsListListener implements ListSelectionListener {
        
        public void valueChanged(ListSelectionEvent e) {
            if (e.getValueIsAdjusting()) return;
            if (_type == null) return;
            _conversationList.clear();
            int selected = fragmentList.getSelectedIndex();
            if (selected == -1) return;
            System.err.println("selected " + selected);
            String key = (String) _flm.getElementAt(selected);
            int count = _model.getConversationCount();
            for (int i=0; i<count; i++) {
                ConversationID id = _model.getConversationAt(i);
                String[] fragments = _model.getConversationProperties(id, _type);
                if (fragments != null) {
                    for (int j=0; j<fragments.length; j++) {
                        if (fragments[j].equals(key)) {
                            _conversationList.addElement(id);
                        }
                    }
                }
            }
        }
    }
    
}
