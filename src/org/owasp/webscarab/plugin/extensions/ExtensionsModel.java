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

import java.util.logging.Logger;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FilteredUrlModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.UrlModel;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.plugin.AbstractPluginModel;

/**
 *
 * @author rdawes
 */
public class ExtensionsModel extends AbstractPluginModel {
    
    private FrameworkModel _model;
    
    private ConversationModel _conversationModel;
    private UrlModel _urlModel;
    
    private String[] _directoryExtensions = { ".zip", ".arj", ".tar", ".tar.gz", ".tar.bz2", ".tgz", ".exe", ".rar", ".tbz"};
    private String[] _fileExtensions = { ".bak", "~", ".old", ".rej", ".orig", ".inc"};
        
    private LinkedList toBeAnalyzedQueue = new LinkedList();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
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
                return url.getParameters() != null || isTested(url);
            }
        };
    }
    
    public void setDirectoryExtensions(String[] extensions) {
        _directoryExtensions = extensions;
    }
    public String[] getDirectoryExtensions() {
        return _directoryExtensions;
    }
    
    public void setFileExtensions(String[] extensions) {
        _fileExtensions = extensions;
    }
    public String[] getFileExtensions() {
        return _fileExtensions;
    }
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    public UrlModel getUrlModel() {
        return _urlModel;
    }
    
    public int getExtensionsTested(HttpUrl url) {
        String checked = _model.getUrlProperty(url, "EXTENSIONS");
        if (checked == null) 
            // to let caller know that URL hasn't been seen yet
            return 0;
        try {
            int count = Integer.parseInt(checked);
            return count;
        } catch (NumberFormatException nfe) {
            _logger.warning("NumberFormatException parsing Extensions property: " + checked);
        }
        return 0;
    }
    
    public void incrementExtensionsTested(HttpUrl url) {
        int count = getExtensionsTested(url);
        _model.setUrlProperty(url, "EXTENSIONS", Integer.toString(++count));
    }
    
    public int getExtensionCount(HttpUrl url) {
        if (url.getPath().endsWith("/")) {
            return (_directoryExtensions == null ? 0 : _directoryExtensions.length);
        } else {
            return (_fileExtensions == null ? 0 : _fileExtensions.length);
        }
    }
    
    public String getExtension(HttpUrl url, int index) {
        if (url.getPath().endsWith("/")) {
            return _directoryExtensions[index];
        } else {
            return _fileExtensions[index];
        }
    }
    
    public boolean isTested(HttpUrl url) {
        return getExtensionsTested(url) >= getExtensionCount(url);
    }

    public void enqueueURL(HttpUrl url) {
        synchronized(toBeAnalyzedQueue) {
            if (!isTested(url)) {
                toBeAnalyzedQueue.addLast(url);
                toBeAnalyzedQueue.notifyAll();
            }
        }
    }
    
    public HttpUrl dequeueURL() {

        synchronized (toBeAnalyzedQueue) {
            try {
                while (toBeAnalyzedQueue.isEmpty()) {
                    toBeAnalyzedQueue.wait();
                }
                return (HttpUrl)toBeAnalyzedQueue.removeFirst();
            }
            catch (InterruptedException e) {
                return null;
            }
            catch(NoSuchElementException e) {
                return null;
            }
        }
    }       
}
