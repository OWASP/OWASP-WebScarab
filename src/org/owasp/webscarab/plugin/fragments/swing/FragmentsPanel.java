/*
 * FragmentsPanel.java
 *
 * Created on August 27, 2004, 11:10 AM
 */

package org.owasp.webscarab.plugin.fragments.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.plugin.fragments.Fragments;

import org.owasp.webscarab.ui.swing.SwingPluginUI;

import javax.swing.JPanel;
import javax.swing.Action;
import javax.swing.AbstractAction;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class FragmentsPanel implements SwingPluginUI {
    
    private Fragments _fragments;
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of FragmentsPanel */
    public FragmentsPanel(Fragments fragments) {
        _fragments = fragments;
    }
    
    public void setModel(SiteModel model) {
        // we only refer to fragments
    }
    
    public Action[] getConversationActions() {
        return new Action[] { 
            new FragmentsAction("CONVERSATION", "SCRIPTS"), 
            new FragmentsAction("CONVERSATION","COMMENTS") 
        };
    }
    
    public void setEnabled(boolean enabled) {
        // FIXME we should do something here
    }
    
    public JPanel getPanel() {
        return null;
    }
    
    public String getPluginName() {
        return "Fragments";
    }
    
    public Action[] getURLActions() {
        return new Action[] { 
            new FragmentsAction("URL", "SCRIPTS"), 
            new FragmentsAction("URL","COMMENTS") 
        };
    }
    
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
}
