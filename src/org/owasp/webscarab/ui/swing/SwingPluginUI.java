/*
 * SwingPlugin.java
 *
 * Created on July 13, 2003, 8:08 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.plugin.PluginUI;
import org.owasp.webscarab.util.swing.ColumnDataModel;

import javax.swing.JPanel;
import javax.swing.Action;

/**
 *
 * @author  rdawes
 */
public interface SwingPluginUI extends PluginUI {

    JPanel getPanel();
    
    Action[] getUrlActions();
    
    ColumnDataModel[] getUrlColumns();
    
    Action[] getConversationActions();
    
    ColumnDataModel[] getConversationColumns();
    
    
}
