/***********************************************************************
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 FedICT
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
 */
package org.owasp.webscarab.plugin.openid.swing;

import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.owasp.webscarab.plugin.openid.AXFetchResponseAttribute;

/**
 *
 * @author Frank Cornelis
 */
public class AXFetchResponseTableModel extends AbstractTableModel {

    private static String[] columnNames = {"Attribute Type", "Value", "Alias", "Signed"};
    private List attributes;

    public AXFetchResponseTableModel() {
        this.attributes = null;
    }

    public void setAttributes(List attributes) {
        this.attributes = attributes;
        int lastRowIndex = getLastRowIndex();
        fireTableRowsInserted(0, lastRowIndex);
    }

    public void resetAttributes() {
        int lastRowIndex = getLastRowIndex();
        this.attributes = null;
        fireTableRowsDeleted(0, lastRowIndex);
    }

    private int getLastRowIndex() {
        if (null == this.attributes) {
            return 0;
        }
        if (this.attributes.isEmpty()) {
            return 0;
        }
        return this.attributes.size() - 1;
    }

    @Override
    public int getRowCount() {
        if (null == this.attributes) {
            return 0;
        }
        return this.attributes.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (null == this.attributes) {
            return null;
        }
        if (rowIndex >= this.attributes.size()) {
            return null;
        }
        AXFetchResponseAttribute attribute = (AXFetchResponseAttribute) this.attributes.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return attribute.getAttributeType();
            case 1:
                return attribute.getValue();
            case 2:
                return attribute.getAlias();
            case 3:
                return attribute.isSigned();
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }
}
