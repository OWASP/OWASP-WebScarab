/*
 * ShowConversationAction.java
 *
 * Created on August 24, 2004, 11:07 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.SiteModel;

import javax.swing.JFrame;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;

/**
 *
 * @author  knoppix
 */
public class ShowConversationAction extends AbstractAction {
    
    private SiteModel _model = null;
    
    /** Creates a new instance of ShowConversationAction */
    public ShowConversationAction() {
        putValue(NAME, "Show conversation");
        putValue(SHORT_DESCRIPTION, "Opens a new window showing the request and response");
        putValue("CONVERSATION", null);
    }
    
    public void setModel(SiteModel model) {
        _model = model;
        setEnabled(false);
    }
    
    public void actionPerformed(ActionEvent e) {
        Object o = getValue("CONVERSATION");
        if (o == null || ! (o instanceof ConversationID)) return;
        ConversationID id = (ConversationID) o;
        Request request = _model.getRequest(id);
        Response response = _model.getResponse(id);
        if (request != null && response != null) {
            String title = "Conversation " + id;
            JFrame frame = FrameCache.getFrame(title);
            if (frame == null) {
                ConversationPanel cp = new ConversationPanel();
                cp.setRequest(request, false);
                cp.setResponse(response, false);
                frame = cp.inFrame(title);
                FrameCache.addFrame(title, frame);
            }
            frame.show();
            frame.toFront();
            frame.requestFocus();
        }
    }
    
    public void putValue(String key, Object value) {
        super.putValue(key, value);
        if (key != null && key.equals("CONVERSATION")) {
            if (value != null && value instanceof ConversationID) {
                setEnabled(true);
            } else {
                setEnabled(false);
            }
        }
    }
    
}
