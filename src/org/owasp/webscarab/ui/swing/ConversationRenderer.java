/*
 * ConversationRenderer.java
 *
 * Created on 19 October 2004, 09:27
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;

/**
 *
 * @author  rogan
 */
public class ConversationRenderer extends JLabel implements ListCellRenderer {
    
    private SiteModel _model;
    
    /** Creates a new instance of ConversationRenderer */
    public ConversationRenderer(SiteModel model) {
        _model = model;
    }
    
    public java.awt.Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        //Get the selected index. (The index param isn't
        //always valid, so just use the value.)
        ConversationID id = (ConversationID) value;
        
        if (isSelected) {
            setBackground(list.getSelectionBackground());
            setForeground(list.getSelectionForeground());
        } else {
            setBackground(list.getBackground());
            setForeground(list.getForeground());
        }
        
        if (id == null || _model == null) {
            setText("");
            return this;
        }
        StringBuffer text = new StringBuffer();
        text.append(id).append(" - ");
        text.append(_model.getConversationProperty(id, "METHOD")).append(" ");
        text.append(_model.getUrlOf(id)).append("    ");
        text.append(_model.getConversationProperty(id, "STATUS"));
        setText(text.toString());
        
        return this;
    }
    
}
