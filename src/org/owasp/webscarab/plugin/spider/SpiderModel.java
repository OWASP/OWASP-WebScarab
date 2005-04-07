/*
 * SpiderModel.java
 *
 * Created on 04 March 2005, 03:11
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.SiteModelEvent;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.FilteredSiteModel;

import java.util.List;
import java.util.LinkedList;

/**
 *
 * @author  rogan
 */
public class SpiderModel extends FilteredSiteModel {
    
    private SiteModel _model;
    private List _linkQueue = new LinkedList();
    
    private String _allowedDomains = null;
    private String _forbiddenPaths = null;
    private boolean _recursive = false;
    private boolean _cookieSync = false;
    
    private NamedValue[] _extraHeaders = null;
    
    /** Creates a new instance of SpiderModel */
    public SpiderModel(SiteModel model) {
        super(model, true, false);
        _model = model;
        parseProperties();
    }
    
    public boolean isUnseen(HttpUrl url) {
        return getConversationCount(url) == 0;
    }
    
    protected boolean shouldFilter(HttpUrl url) {
        return ! isUnseen(url);
    }
    
    public void addUnseenLink(HttpUrl url, HttpUrl referer) {
        if (url == null) {
            return;
        }
        if (isUnseen(url)) {
            String first = _model.getUrlProperty(url, "REFERER");
            if (first == null || first.equals("")) {
                _model.setUrlProperty(url, "REFERER", referer.toString());
            }
        }
    }
    
    public void queueLink(Link link) {
        try {
            _model.readLock().acquire();
            _linkQueue.add(link);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
    }
    
    public Link dequeueLink() {
        try {
            _model.readLock().acquire();
            if (_linkQueue.size() == 0) return null;
            Link link = (Link) _linkQueue.remove(0);
            return link;
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return null;
    }
    
    public void clearLinkQueue() {
        try {
            _model.readLock().acquire();
            _linkQueue.clear();
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
    }
    
    public int getQueuedLinkCount() {
        try {
            _model.readLock().acquire();
            return _linkQueue.size();
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return 0;
    }
    
    public void parseProperties() {
        String prop = "Spider.domains";
        String value = Preferences.getPreference(prop, ".*localhost.*");
        setAllowedDomains(value);
        
        prop = "Spider.excludePaths";
        value = Preferences.getPreference(prop, "");
        setForbiddenPaths(value);
        
        prop = "Spider.synchroniseCookies";
        value = Preferences.getPreference(prop, "true");
        setCookieSync(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
        
        prop = "Spider.recursive";
        value = Preferences.getPreference(prop, "false");
        setRecursive(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getReferer(HttpUrl url) {
        return _model.getUrlProperty(url, "REFERER");
    }
    
    public void setExtraHeaders(NamedValue[] headers) {
        _extraHeaders = headers;
    }
    
    public NamedValue[] getExtraHeaders() {
        return _extraHeaders;
    }
    
    public void setRecursive(boolean bool) {
        _recursive = bool;
        String prop = "Spider.recursive";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }
    
    public boolean getRecursive() {
        return _recursive;
    }
    
    public void setCookieSync(boolean enabled) {
        _cookieSync = enabled;
        String prop = "Spider.synchroniseCookies";
        Preferences.setPreference(prop,Boolean.toString(enabled));
    }
    
    public boolean getCookieSync() {
        return _cookieSync;
    }
    
    public void setAllowedDomains(String regex) {
        _allowedDomains = regex;
        String prop = "Spider.domains";
        Preferences.setPreference(prop,regex);
    }
    
    public String getAllowedDomains() {
        return _allowedDomains;
    }
    
    public void setForbiddenPaths(String regex) {
        _forbiddenPaths = regex;
        String prop = "Spider.excludePaths";
        Preferences.setPreference(prop,regex);
    }
    
    public String getForbiddenPaths() {
        return _forbiddenPaths;
    }
    
    public void setAuthRequired(HttpUrl url) {
        _model.setUrlProperty(url, "AUTHREQUIRED", Boolean.toString(true));
    }
    
}
