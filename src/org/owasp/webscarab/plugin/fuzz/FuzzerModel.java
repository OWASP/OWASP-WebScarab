/*
 * FuzzerModel.java
 *
 * Created on 06 February 2005, 08:36
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.FilteredSiteModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.ConversationID;

import java.util.logging.Logger;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedList;

/**
 *
 * @author  rogan
 */
public class FuzzerModel extends FilteredSiteModel {
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private Map _signatures = new HashMap();
    
    private List _queuedUrls = new LinkedList();
    
    /** Creates a new instance of FuzzerModel */
    public FuzzerModel(SiteModel model) {
        super(model, true, false);
    }
    
    protected boolean shouldFilter(HttpUrl url) {
        return url.getParameters() != null || _model.getConversationCount(url) == 0;
    }
    
    public void addSignature(HttpUrl url, Signature signature) {
        _logger.info("Adding a signature for " + url + " = " + signature);
        List signatures = (List) _signatures.get(url);
        if (signatures == null) {
            signatures = new ArrayList();
            _signatures.put(url, signatures);
        }
        if (signatures.indexOf(signature)<0) {
            signatures.add(signature);
            fireSignatureAdded(url, signatures.size()-1);
        }
    }
    
    public int getSignatureCount(HttpUrl url) {
        List signatures = (List) _signatures.get(url);
        if (signatures == null) return 0;
        return signatures.size();
    }
    
    public Signature getSignature(HttpUrl url, int i) {
        List signatures = (List) _signatures.get(url);
        if (signatures == null) return null;
        return (Signature) signatures.get(i);
    }
    
    public boolean isAppCandidate(HttpUrl url) {
        List signatures = (List) _signatures.get(url);
        String blank = _model.getUrlProperty(url, "BLANKREQUEST");
        String cookie = _model.getUrlProperty(url, "SET-COOKIE");
        if (cookie != null && !cookie.equals("")) return true;
        if (signatures != null && (blank == null || blank.equals(""))) {
            return true;
        }
        return false;
    }
    
    public void setBlankRequest(HttpUrl url) {
        _model.setUrlProperty(url, "BLANKREQUEST", "true");
    }
    
    public void setConversationError(ConversationID id) {
        _model.setConversationProperty(id, "ERRORS", "true");
        _model.setUrlProperty(_model.getUrlOf(id), "ERRORS", "true");
    }
    
    public boolean isApp(HttpUrl url) {
        return _model.getUrlProperties(url, "CHECKSUM").length > 1;
    }
    
    public void addCheckSum(HttpUrl url, String checksum) {
        _model.addUrlProperty(url, "CHECKSUM", checksum);
    }
    
    public void queueUrl(HttpUrl url) {
        _queuedUrls.add(url);
    }
    
    public int getQueuedUrlCount() {
        return _queuedUrls.size();
    }
    
    public HttpUrl getQueuedUrl() {
        if (_queuedUrls.size() > 0) return (HttpUrl) _queuedUrls.remove(0);
        _logger.warning("Requested a non-existent url");
        return null;
    }
    
    public void clearUrlQueue() {
        _queuedUrls.clear();
    }
    
    /**
     * tells listeners that the url's app status has changed
     * @param url the url
     */
    protected void fireAppStatusChanged(HttpUrl url, boolean status) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.URL_APPSTATUS_CHANGED, url);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).appStatusChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    public void addModelListener(FuzzerListener listener) {
        super.addModelListener(listener);
        _listenerList.add(FuzzerListener.class, listener);
    }
    
    /**
     * tells listeners that the url's app status has changed
     * @param url the url
     */
    protected void fireSignatureAdded(HttpUrl url, int position) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.URL_SIGNATURE_ADDED, url);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).signatureAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    public void dataChanged() {
        _signatures.clear();
    }
    
}
