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
 * MessagePanel.java
 *
 * Created on November 6, 2003, 8:43 AM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Message;
import org.owasp.webscarab.model.NamedValue;

import javax.swing.event.TableModelListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;

import java.util.Vector;

import java.awt.Component;
import javax.swing.table.TableCellEditor;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;

/**
 *
 * @author  rdawes
 */
public class MessagePanel extends javax.swing.JPanel {
    
    private ContentPanel _cp;
    private Message _message = null;
    private boolean _editable = false;
    private boolean _modified = false;
    private HeaderTableModel _tableModel;
    private Vector _columns;
    
    private NamedValue[] NO_HEADERS = new NamedValue[0];
    
    /** Creates new form MessagePanel */
    public MessagePanel() {
        initComponents();
        setName("Message");
        
        _tableModel  = new HeaderTableModel();
        _tableModel.addTableModelListener(new TableModelListener() {
            public void tableChanged(TableModelEvent e) {
                _modified = true;
            }
        });
        headerTable.setModel(_tableModel);
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(500);
        
        _cp = new ContentPanel();
        messageSplitPane.setRightComponent(_cp);
        String dividerLocation = Preferences.getPreference("MessagePanel.dividerLocation");
        if (dividerLocation != null) {
            try {
                messageSplitPane.setDividerLocation(Integer.parseInt(dividerLocation));
            } catch (NumberFormatException nfe) {}
        }
        messageSplitPane.addPropertyChangeListener(new PropertyChangeListener() {
            public void propertyChange(PropertyChangeEvent e) {
                if (e.getPropertyName().equals("dividerLocation")) {
                    Preferences.setPreference("MessagePanel.dividerLocation", e.getNewValue().toString());
                }
            }
        });
        setEditable(false);
        setMessage(null);
    }
    
    public MessagePanel(int orientation) {
        this();
        messageSplitPane.setOrientation(orientation);
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        buttonPanel.setVisible(_editable);
        java.awt.Color color;
        if (_editable) {
            color = new java.awt.Color(255, 255, 255);
        } else {
            color = new java.awt.Color(204, 204, 204);
        }
        headerTable.setBackground(color);
        _tableModel.setEditable(editable);
        _cp.setEditable(editable);
    }
    
    public void setMessage(Message message) {
        _modified = false;
        _message = message;
        
        if (message != null) {
            _tableModel.setHeaders(_message.getHeaders());
            byte[] content = message.getContent();
            if (_editable || (content.length > 0)) {
                _cp.setContentType(message.getHeader("Content-Type"));
                _cp.setContent(content);
                _cp.setVisible(true);
            } else {
                _cp.setVisible(false);
            }
        } else {
            _tableModel.setHeaders(NO_HEADERS);
            _cp.setContentType(null);
            _cp.setContent(null);
        }
        invalidate();
        revalidate();
    }
    
    public Message getMessage() {
        if (_editable) {
            if (isModified() && _message != null) {
                _message.setHeaders(_tableModel.getHeaders());
            }
            if (_cp.isModified()) {
                _message.setContent(_cp.getContent());
                if (_message.getHeader("Content-Length") != null) {
                    _message.setHeader(new NamedValue("Content-Length", Integer.toString(_message.getContent().length)));
                }
            }
        }
        return _message;
    }
    
    public boolean isModified() {
        if (headerTable.isEditing()) {
            headerTable.getCellEditor().stopCellEditing();
        }
        return _editable && (_modified || _cp.isModified());
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        messageSplitPane = new javax.swing.JSplitPane();
        headerPanel = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        headerTable = new javax.swing.JTable();
        buttonPanel = new javax.swing.JPanel();
        insertButton = new javax.swing.JButton();
        deleteButton = new javax.swing.JButton();

        setLayout(new java.awt.GridBagLayout());

        setPreferredSize(new java.awt.Dimension(400, 200));
        messageSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        messageSplitPane.setResizeWeight(0.3);
        messageSplitPane.setContinuousLayout(true);
        messageSplitPane.setDoubleBuffered(true);
        messageSplitPane.setOneTouchExpandable(true);
        headerPanel.setLayout(new java.awt.GridBagLayout());

        headerPanel.setMaximumSize(new java.awt.Dimension(2147483647, 200));
        headerPanel.setMinimumSize(new java.awt.Dimension(200, 50));
        headerPanel.setPreferredSize(new java.awt.Dimension(200, 200));
        jScrollPane1.setMinimumSize(new java.awt.Dimension(200, 50));
        headerTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null},
                {null, null},
                {null, null},
                {null, null}
            },
            new String [] {
                "Name", "Value"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        jScrollPane1.setViewportView(headerTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        headerPanel.add(jScrollPane1, gridBagConstraints);

        buttonPanel.setLayout(new java.awt.GridBagLayout());

        insertButton.setText("Insert");
        insertButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                insertButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.SOUTH;
        buttonPanel.add(insertButton, gridBagConstraints);

        deleteButton.setText("Delete");
        deleteButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTH;
        buttonPanel.add(deleteButton, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        headerPanel.add(buttonPanel, gridBagConstraints);

        messageSplitPane.setLeftComponent(headerPanel);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(messageSplitPane, gridBagConstraints);

    }//GEN-END:initComponents
    
    private void deleteButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteButtonActionPerformed
        int rowIndex = headerTable.getSelectedRow();
        if (rowIndex > -1) {
            _tableModel.removeRow(rowIndex);
        }
    }//GEN-LAST:event_deleteButtonActionPerformed
    
    private void insertButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_insertButtonActionPerformed
        int rowIndex = headerTable.getSelectedRow();
        if (rowIndex > -1) {
            _tableModel.insertRow(rowIndex);
        } else {
            _tableModel.insertRow(_tableModel.getRowCount());
        }
    }//GEN-LAST:event_insertButtonActionPerformed
    
    public static void main(String[] args) {
        byte[] content = new byte[0];
        org.owasp.webscarab.model.Response response = new org.owasp.webscarab.model.Response();
        try {
            String resp = "/home/rogan/workspace/webscarab/test/data/index-resp";
            if (args.length == 1) {
                resp = args[0];
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(resp);
            response.read(fis);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
        
        javax.swing.JFrame top = new javax.swing.JFrame("Message Pane");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        
        javax.swing.JButton button = new javax.swing.JButton("GET");
        final MessagePanel mp = new MessagePanel();
        top.getContentPane().add(mp);
        top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                System.out.println(mp.getMessage());
            }
        });
        // top.setBounds(100,100,600,400);
        top.pack();
        top.show();
        try {
            mp.setEditable(false);
            mp.setMessage(response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel buttonPanel;
    private javax.swing.JButton deleteButton;
    private javax.swing.JPanel headerPanel;
    private javax.swing.JTable headerTable;
    private javax.swing.JButton insertButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSplitPane messageSplitPane;
    // End of variables declaration//GEN-END:variables
    
    private class HeaderTableModel extends AbstractTableModel {
        
        private Vector _headers = new Vector();
        private boolean _editable = false;
        private String[] _names = new String[] { "Header", "Value"};
        
        private void setEditable(boolean editable) {
            _editable = editable;
        }
        
        public String getColumnName(int column) {
            return _names[column];
        }
        
        public void setHeaders(NamedValue[] headers) {
            _headers.clear();
            for (int i=0; i<headers.length; i++) {
                _headers.add(headers[i]);
            }
            fireTableDataChanged();
        }
        
        public NamedValue[] getHeaders() {
            return (NamedValue[]) _headers.toArray(NO_HEADERS);
        }
        
        public int getColumnCount() {
            return 2;
        }
        
        public int getRowCount() {
            return _headers.size();
        }
        
        public Object getValueAt(int row, int column) {
            NamedValue nv = (NamedValue) _headers.get(row);
            if (column == 0) return nv.getName();
            return nv.getValue();
        }
        
        public void insertRow(int row) {
            _headers.add(row, new NamedValue("Header", "value"));
            fireTableRowsInserted(row, row);
        }
        
        public void removeRow(int row) {
            _headers.remove(row);
            fireTableRowsDeleted(row, row);
        }
        
        public void setValueAt(Object aValue, int row, int col) {
            if (_editable && aValue instanceof String) {
                NamedValue nv = (NamedValue) _headers.get(row);
                if (col == 0) {
                    _headers.set(row, new NamedValue((String)aValue, nv.getValue()));
                } else {
                    _headers.set(row, new NamedValue(nv.getName(), (String) aValue));
                }
                fireTableCellUpdated(row, col);
            }
        }
        
        public boolean isCellEditable(int row, int column) {
            return _editable;
        }
        
    }
    
}
