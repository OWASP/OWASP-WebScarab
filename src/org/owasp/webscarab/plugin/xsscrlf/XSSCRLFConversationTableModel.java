/*
 * XSSCRLFConversationTableModel.java
 *
 * Created on 5 Май 2006 г., 14:54
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.xsscrlf;

import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.AbstractConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.ConversationListener;
import org.owasp.webscarab.model.ConversationEvent;

import org.owasp.webscarab.util.swing.ExtensibleTableModel;
import org.owasp.webscarab.util.swing.ColumnDataModel;

import javax.swing.table.AbstractTableModel;
import javax.swing.SwingUtilities;

/**
 *
 * @author meder
 */
public class XSSCRLFConversationTableModel extends ConversationTableModel {
    
    /** Creates a new instance of XSSCRLFConversationTableModel */
    public XSSCRLFConversationTableModel(ConversationModel model) {
        super(model);        
        addProperty();
    }
    
    private void addProperty() {
        
        ColumnDataModel cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                HttpUrl url = _model.getRequest((ConversationID)key).getURL();
                String retval = ((AbstractConversationModel)_model).getUrlProperty((ConversationID) key, "XSS/CRLF");
                if (retval == null) retval="N/A";
                return retval;
            }
            public String getColumnName() { return "Vulnerability"; }
            public Class getColumnClass() { return String.class; }
        };
        addColumn(cdm);
    }
    
    
}
