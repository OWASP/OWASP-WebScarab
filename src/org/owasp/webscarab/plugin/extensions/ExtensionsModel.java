/*
 * ExtensionsModel.java
 *
 * Created on 04 December 2005, 09:12
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.extensions;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FilteredUrlModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.UrlModel;
import org.owasp.webscarab.plugin.AbstractPluginModel;

/**
 *
 * @author rdawes
 */
public class ExtensionsModel extends AbstractPluginModel {
    
    private FrameworkModel _model;
    
    private ConversationModel _conversationModel;
    private UrlModel _urlModel;
    
    /** Creates a new instance of ExtensionsModel */
    public ExtensionsModel(FrameworkModel model) {
        _model = model;
        _conversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
            public boolean shouldFilter(ConversationID id) {
                return !getConversationOrigin(id).equals("Extensions");
            }
        };
        
        _urlModel = new FilteredUrlModel(model.getUrlModel()) {
            public boolean shouldFilter(HttpUrl url) {
                return isTested(url);
            }
        };
    }
    
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    public UrlModel getUrlModel() {
        return _urlModel;
    }
    
    private int getExtensionCount(HttpUrl url) {
        // check whether a file or directory, return appropriate value
    }
    
    private boolean isTested(HttpUrl url) {
        String tested = _model.getUrlProperty(url, "Extensions");
        if (tested == null) return false;
        try {
            int count = Integer.parseInt(tested);
            if (count > getExtensionCount(url)) 
                return true;
        } catch (NumberFormatException nfe) {
            _logger.warning("NumberFormatException parsing Extensions property: " + tested);
        }
        return false;
    }
    
}
