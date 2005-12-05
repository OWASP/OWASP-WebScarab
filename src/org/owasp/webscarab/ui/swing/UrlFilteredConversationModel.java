/*
 * UrlFilteredConversationModel.java
 *
 * Created on 06 October 2005, 04:03
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author rdawes
 */
public class UrlFilteredConversationModel extends FilteredConversationModel {
    
    private ConversationModel _model;
    private HttpUrl _url = null;
    
    /** Creates a new instance of UrlFilteredConversationModel */
    public UrlFilteredConversationModel(FrameworkModel model, ConversationModel cmodel) {
        super(model, cmodel);
        _model = cmodel;
    }
    
    public void setUrl(HttpUrl url) {
        if (url == _url) {
            return;
        } else if (_url == null && url != null || _url != null && url == null || !_url.equals(url)) {
            _url = url;
            updateConversations();
        }
    }
    
    public boolean shouldFilter(ConversationID id) {
        if (_url == null) {
            return false;
        } else {
            return ! _url.equals(_model.getRequestUrl(id));
        }
    }
    
}
