/*
 * ManualRequestModel.java
 *
 * Created on 01 May 2005, 11:12
 */

package org.owasp.webscarab.plugin.manualrequest;

import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.AbstractPluginModel;

/**
 *
 * @author  rogan
 */
public class ManualRequestModel extends AbstractPluginModel {
    
    private FrameworkModel _model;
    
    /** Creates a new instance of ManualRequestModel */
    public ManualRequestModel(FrameworkModel model) {
        _model = model;
    }
    
    public ConversationModel getConversationModel() {
        return _model.getConversationModel();
    }
    
    public Cookie[] getCookiesForUrl(HttpUrl url) {
        return _model.getCookiesForUrl(url);
    }
    
    public void addCookie(Cookie cookie) {
        _model.addCookie(cookie);
    }
    
}
