/*
 * FilteredUrlModel.java
 *
 * Created on 04 March 2005, 10:35
 */

package org.owasp.webscarab.model;

import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import javax.swing.event.EventListenerList;

import java.util.logging.Logger;
import java.util.logging.Level;

import org.owasp.webscarab.util.MRUCache;

/**
 *
 * @author  rogan
 */
public abstract class FilteredUrlModel extends AbstractUrlModel {
    
    protected UrlModel _urlModel;
    private Set _filteredUrls = null;
    private Set _implicitUrls = null;
    
    private MRUCache _cache = new MRUCache(16);
    
    protected EventListenerList _listenerList = new EventListenerList();
    
    protected Logger _logger = Logger.getLogger(getClass().getName());
    
    private boolean _updating = false;
    
    private int hit, miss = 0;
    
    /** Creates a new instance of FilteredUrlModel */
    public FilteredUrlModel(UrlModel urlModel) {
        _logger.setLevel(Level.INFO);
        _urlModel = urlModel;
        try {
            _urlModel.readLock().acquire();
            updateFilteredUrls();
            _urlModel.addUrlListener(new Listener());
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _urlModel.readLock().release();
        }
    }
    
    public Sync readLock() {
        return _urlModel.readLock();
    }
    
    protected void initFilters() {
        _filteredUrls = new HashSet();
        _implicitUrls = new HashSet();
    }
    
    protected abstract boolean shouldFilter(HttpUrl url);
    
    protected boolean isFiltered(HttpUrl url) {
        return _filteredUrls != null && _filteredUrls.contains(url);
    }
    
    protected void setFiltered(HttpUrl url, boolean filtered) {
        if (filtered) {
            _filteredUrls.add(url);
        } else {
            _filteredUrls.remove(url);
        }
    }
    
    public boolean isImplicit(HttpUrl url) {
        return _implicitUrls.contains(url);
    }
    
    protected void setImplicit(HttpUrl url, boolean filtered) {
        if (_implicitUrls == null) _implicitUrls = new HashSet();
        if (filtered) {
            _implicitUrls.add(url);
        } else {
            _implicitUrls.remove(url);
        }
    }
    
    private boolean isVisible(HttpUrl url) {
        return isImplicit(url) || ! isFiltered(url);
    }
    
    public int getIndexOf(HttpUrl url) {
        int index = Collections.binarySearch(getFilteredChildren(url), url);
        return index < 0 ? -1 : index;
    }
    
    public HttpUrl getChildAt(HttpUrl url, int index) {
        return (HttpUrl) getFilteredChildren(url).get(index);
    }
    
    private void updateFilteredUrls() {
        initFilters();
        recurseTree(null);
    }
    
    private ArrayList getFilteredChildren(HttpUrl parent) {
        ArrayList childList = (ArrayList) _cache.get(parent);
        if (childList != null) {
            hit++;
            return childList;
        }
        try {
            childList = new ArrayList();
            _urlModel.readLock().acquire();
            int count = _urlModel.getChildCount(parent);
            for (int i=0; i<count; i++) {
                HttpUrl child = _urlModel.getChildAt(parent, i);
                if (isVisible(child)) 
                    childList.add(child);
            }
            if (count > 0) { // we are saving some real work here
                miss++;
                _logger.fine("Hit=" + hit + ", miss=" + miss + " parent = " + parent + " count="+count);
                _cache.put(parent, childList);
            }
            return childList;
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _urlModel.readLock().release();
        }
        return null;
    }
    
    public int getChildCount(HttpUrl url) {
        return getFilteredChildren(url).size();
    }
    
    private void recurseTree(HttpUrl parent) {
        int count = _urlModel.getChildCount(parent);
        for (int i=0; i<count; i++) {
            HttpUrl url = _urlModel.getChildAt(parent, i);
            if (shouldFilter(url)) {
                setFiltered(url, true);
            } else {
                grow(url);
            }
            recurseTree(url);
        }
    }
    
    /* adds url, and marks any previously filtered intermediate nodes as implicit
     * fires events for all node that becomes visible
     */
    private void grow(HttpUrl url) {
        HttpUrl[] path = url.getUrlHierarchy();
        for (int i=0; i<path.length-1; i++) {
            if (! isVisible(path[i])) {
                setImplicit(path[i], true);
                if (i==0) { // update the root node
                    _cache.remove(null);
                } else {
                    _cache.remove(path[i-1]);
                }
                if (!_updating)
                    fireUrlAdded(path[i], -1); //FIXME
            }
        }
        _cache.remove(url.getParentUrl());
        if (!_updating)
            fireUrlAdded(url, 0); // FIXME
    }
    
    /* removes url and any implicit parents. Fires events for the all urls removed
     *
     */
    private void prune(HttpUrl url) {
        _cache.remove(url.getParentUrl());
        if (!_updating)
            fireUrlRemoved(url, -1); // FIXME
        HttpUrl[] path = url.getUrlHierarchy();
        for (int i=path.length-2; i>=0; i--) {
            if (isImplicit(path[i]) && getChildCount(path[i])==0) {
                setImplicit(path[i], false);
                if (i==0) { // update the root node
                    _cache.remove(null);
                } else {
                    _cache.remove(path[i-1]);
                }
                if (!_updating)
                    fireUrlRemoved(path[i], -1); // FIXME
            }
        }
    }
    
    public void reset() {
        _cache.clear();
        _updating = true;
        updateFilteredUrls();
        _updating = false;
        fireUrlsChanged();
    }
    
    private class Listener implements UrlListener {
        
        public Listener() {
        }
        
        public void urlsChanged() {
            reset();
        }
        
        public void urlAdded(UrlEvent evt) {
            HttpUrl url = evt.getUrl();
            if (! shouldFilter(url)) {
                grow(url);
            } else {
                setFiltered(url, true);
            }
        }
        
        public void urlChanged(UrlEvent evt) {
            HttpUrl url = evt.getUrl();
            if (shouldFilter(url)) { // it is now filtered
                if (isVisible(url)) { // we could previously see it
                    if (getChildCount(url)>0) { // it has children
                        setFiltered(url, true);
                        setImplicit(url, true);
                        if (!_updating)
                            fireUrlChanged(url, -1); // FIXME
                    } else { // it has no children, hide it and any implicit parents
                        setFiltered(url, true);
                        prune(url);
                    }
                } // else there is nothing to do to an already invisible node
            } else { // it is now not filtered
                if (! isVisible(url)) { // it was previously hidden
                    setFiltered(url, false);
                    grow(url);
                } else if (!_updating) {
                    fireUrlChanged(url, -1); // FIXME
                }
            }
        }
        
        public void urlRemoved(UrlEvent evt) {
            HttpUrl url = evt.getUrl();
            if (isVisible(url)) {
                prune(url);
            } else {
                setFiltered(url, false);
            }
        }
        
    }
    
}

