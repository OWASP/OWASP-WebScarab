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

package org.owasp.webscarab.ui.swing.editors;

import javax.swing.event.TableModelListener;
import javax.swing.event.TableModelEvent;

import javax.swing.table.DefaultTableModel;
import java.io.UnsupportedEncodingException;

import java.util.Vector;

import java.awt.Component;
import javax.swing.CellEditor;

import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author  rdawes
 */
public class UrlEncodedPanel extends javax.swing.JPanel implements ByteArrayEditor {
    
    private boolean _editable = false;
    private boolean _modified = false;
    private Vector _columns;
    private DefaultTableModel _tableModel;
    private String _data = null;
    
    /** Creates new form MessagePanel */
    public UrlEncodedPanel() {
        initComponents();
        setName("URLEncoded");
        _columns = new Vector();
        _columns.add("Variable");
        _columns.add("Value");
        _tableModel  = new DefaultTableModel(_columns.toArray(), 0);
        _tableModel.addTableModelListener(new TableModelListener() {
            public void tableChanged(TableModelEvent e) {
                _modified = true;
            }
        });
        headerTable.setModel(_tableModel);
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(500);
        setEditable(_editable);
    }
    
    public String[] getContentTypes() {
        return new String[] { "application/x-www-form-urlencoded" };
    }
    
    public void setBytes(String contentType, byte[] bytes) {
        if (bytes == null) {
            _data = null;
            _tableModel.setDataVector(null, _columns);
        } else {
            try {
                _data = new String(bytes, "UTF-8");
            } catch (UnsupportedEncodingException e) {}
            String[] variables = _data.split("&");
            String[][] pairs = new String[variables.length][2];
            for (int i=0; i<variables.length; i++) {
                String[] parts = variables[i].split("=",2);
                if (parts.length > 0) {
                    pairs[i][0] = Encoding.urlDecode(parts[0]);
                }
                if (parts.length > 1) {
                    pairs[i][1] = Encoding.urlDecode(parts[1]);
                }
            }
            _tableModel.setDataVector(pairs, _columns.toArray());
        }
        _modified = false;
    }
    
    public byte[] getBytes() {
        if (_editable && isModified()) {
            StringBuffer buff = new StringBuffer();
            Vector pairs = _tableModel.getDataVector();
            for (int i=0; i<pairs.size(); i++) {
                Vector v = (Vector) pairs.elementAt(i);
                String name = (String) v.elementAt(0);
                if (name == null || name.equals("")) continue;
                String value = (String) v.elementAt(1);
                if (value == null) value = "";
                if (i>0) buff.append("&");
                buff.append(Encoding.urlEncode(name)).append("=").append(Encoding.urlEncode(value));
            }
            _data = buff.toString();
        }
        if (_data == null) {
            return new byte[0];
        } else {
            try {
                return _data.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                return new byte[0];
            }
        }
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        buttonPanel.setVisible(_editable);
        java.awt.Color color;
        if (_editable) {
            color = java.awt.Color.WHITE;
        } else {
            color = new java.awt.Color(204, 204, 204);
        }
        headerTable.setBackground(color);
    }
    
    public boolean isModified() {
        if (headerTable.isEditing()) {
            headerTable.getCellEditor().stopCellEditing();
        }
        return _editable && _modified;
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        jScrollPane1 = new javax.swing.JScrollPane();
        headerTable = new javax.swing.JTable();
        buttonPanel = new javax.swing.JPanel();
        insertButton = new javax.swing.JButton();
        deleteButton = new javax.swing.JButton();

        setLayout(new java.awt.GridBagLayout());

        setPreferredSize(new java.awt.Dimension(402, 102));
        jScrollPane1.setMinimumSize(new java.awt.Dimension(200, 50));
        headerTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_ALL_COLUMNS);
        jScrollPane1.setViewportView(headerTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(jScrollPane1, gridBagConstraints);

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
        add(buttonPanel, gridBagConstraints);

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
            _tableModel.insertRow(rowIndex, new Object[2]);
        } else {
            _tableModel.insertRow(_tableModel.getRowCount(), new Object[2]);
        }
    }//GEN-LAST:event_insertButtonActionPerformed
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel buttonPanel;
    private javax.swing.JButton deleteButton;
    private javax.swing.JTable headerTable;
    private javax.swing.JButton insertButton;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
    
}
