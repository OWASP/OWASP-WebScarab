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

import java.util.LinkedList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.openid4java.association.Association;

/**
 *
 * @author Frank Cornelis
 */
public class AssociationTableModel extends AbstractTableModel {
    private static String[] columnNames = {"Handle", "Type", "Expiry"};
    private List associations;

    public AssociationTableModel() {
        this.associations = new LinkedList();
    }

    public void addAssociation(Association association) {
        this.associations.add(association);
        int lastRowIndex = getLastRowIndex();
        fireTableRowsInserted(0, lastRowIndex);
    }

    private int getLastRowIndex() {
        if (this.associations.isEmpty()) {
            return 0;
        }
        return this.associations.size() - 1;
    }

    @Override
    public int getRowCount() {
        return this.associations.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex >= this.associations.size()) {
            return null;
        }
        Association association = (Association) this.associations.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return association.getHandle();
            case 1:
                return association.getType();
            case 2:
                return association.getExpiry();
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }
}
