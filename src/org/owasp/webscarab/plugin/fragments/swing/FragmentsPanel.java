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
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.MultiLineCellRenderer;
import org.owasp.webscarab.util.swing.ListComboBoxModel;

import javax.swing.JPanel;
import javax.swing.Action;
import javax.swing.AbstractAction;
import javax.swing.DefaultListModel;
import javax.swing.SwingUtilities;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

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
    
    private Action[] _conversationActions;
    private Action[] _urlActions;
    private Map _conversationColumns = new HashMap();
    private Map _urlColumns = new HashMap();
    
    private DefaultListModel _typeListModel = new DefaultListModel();
    private FragmentListModel _flm = new FragmentListModel();
    
    private Listener _listener = new Listener();
    
    private static final ColumnDataModel[] CDM = new ColumnDataModel[0];
    
    /** Creates new form FragmentsPanel */
    public FragmentsPanel(Fragments fragments) {
        initComponents();
        fragmentList.setCellRenderer(new MultiLineCellRenderer());
        fragmentList.setModel(_flm);
        
        typeComboBox.setModel(new ListComboBoxModel(_typeListModel));
        typeComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String type = (String) typeComboBox.getSelectedItem();
                _flm.setFilter(null, type);
            }
        });
        
        _fragments = fragments;
        createActions();
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
        typeComboBox = new javax.swing.JComboBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        fragmentList = new javax.swing.JList();

        setLayout(new java.awt.BorderLayout());

        add(typeComboBox, java.awt.BorderLayout.NORTH);

        jScrollPane1.setViewportView(fragmentList);

        add(jScrollPane1, java.awt.BorderLayout.CENTER);

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
    
    public void setModel(SiteModel model) {
        if (_model != null) {
            _model.removeSiteModelListener(_listener);
            _typeListModel.clear();
        }
        _model = model;
        if (model != null) {
            _model.addSiteModelListener(_listener);
            int count = _fragments.getFragmentTypeCount();
            _logger.info("Model has " + count + " fragment types");
            for (int i=0; i<count; i++) 
                _typeListModel.addElement(_fragments.getFragmentType(i));
        }
    }
    
    public void fragmentAdded(HttpUrl url, ConversationID id, final String type, final String key) {
        _logger.info(type + " added " + id + " key = " + key);
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                if (_typeListModel.indexOf(type) < 0) _typeListModel.addElement(type);
                _flm.fragmentAdded(type, key);
            }
        });
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JList fragmentList;
    private javax.swing.JScrollPane jScrollPane1;
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
        
    }
    
    private class FragmentListModel extends AbstractListModel {
        
        private String _type = null;
        private Object _id = null;
        
        public FragmentListModel() {
        }
        
        public void setFilter(Object id, String type) {
            fireIntervalRemoved(this, 0, getSize());
            _id = id;
            _type = type;
            fireIntervalAdded(this, 0, getSize());
        }
        
        public Object getElementAt(int index) {
            String key = _fragments.getFragmentKeyAt(_type, index);
            return _fragments.getFragment(key);
        }
        
        public int getSize() {
            if (_type == null) return 0;
            return _fragments.getFragmentCount(_type);
        }
        
        public void fragmentAdded(String type, String key) {
            if (_type == null || !_type.equals(type)) return;
            int row = _fragments.indexOfFragment(type, key);
            fireIntervalAdded(this, row, row);
        }
    }
    
}
