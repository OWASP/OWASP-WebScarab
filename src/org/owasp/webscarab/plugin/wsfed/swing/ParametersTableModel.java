/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2010-2011 FedICT
 * Copyright (c) 2010 Frank Cornelis <info@frankcornelis.be>
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

package org.owasp.webscarab.plugin.wsfed.swing;

import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.owasp.webscarab.model.NamedValue;

/**
 *
 * @author Frank Cornelis
 */
public class ParametersTableModel extends AbstractTableModel {

    private static String[] columnNames = {"Name", "Value"};

    private List parameters;

    public ParametersTableModel() {
        this.parameters = null;
    }

    public void setParameters(List parameters) {
        this.parameters = parameters;
        int lastRowIndex = getLastRowIndex();
        fireTableRowsInserted(0, lastRowIndex);
    }

    public void resetParameters() {
        int lastRowIndex = getLastRowIndex();
        this.parameters = null;
        fireTableRowsDeleted(0, lastRowIndex);
    }

    private int getLastRowIndex() {
        if (null == this.parameters) {
            return 0;
        }
        if (this.parameters.isEmpty()) {
            return 0;
        }
        return this.parameters.size() - 1;
    }

    @Override
    public int getRowCount() {
        if (null == this.parameters) {
            return 0;
        }
        return this.parameters.size();
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (null == this.parameters) {
            return null;
        }
        if (rowIndex >= this.parameters.size()) {
            return null;
        }
        NamedValue namedValue = (NamedValue) this.parameters.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return namedValue.getName();
            case 1:
                return namedValue.getValue();
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }
}
