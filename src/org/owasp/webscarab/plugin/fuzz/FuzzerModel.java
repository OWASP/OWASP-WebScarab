/*
 * FuzzerModel.java
 *
 * Created on 06 February 2005, 08:36
 */

package org.owasp.webscarab.plugin.fuzz;

import EDU.oswego.cs.dl.util.concurrent.Sync;
import java.beans.PropertyChangeSupport;
import java.net.MalformedURLException;
import org.owasp.webscarab.model.AbstractConversationModel;
import org.owasp.webscarab.model.ConversationModel;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.FrameworkEvent;
import org.owasp.webscarab.model.FrameworkListener;
import org.owasp.webscarab.model.FilteredUrlModel;
import org.owasp.webscarab.model.UrlModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.NamedValue;

import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

import org.owasp.webscarab.plugin.AbstractPluginModel;

import java.util.logging.Logger;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import javax.swing.event.EventListenerList;

/**
 *
 * @author  rogan
 */
public class FuzzerModel extends AbstractPluginModel {
    
    public final static String PROPERTY_FUZZMETHOD = "FuzzMethod";
    public final static String PROPERTY_FUZZURL = "FuzzUrl";
    public final static String PROPERTY_FUZZVERSION = "FuzzVersion";
    public final static String PROPERTY_REQUESTINDEX = "RequestIndex";
    public final static String PROPERTY_TOTALREQUESTS = "TotalRequests";
    public final static String PROPERTY_BUSYFUZZING = "BusyFuzzing";
    
    private FrameworkModel _model = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private EventListenerList _listenerList = new EventListenerList();
    private ReentrantReaderPreferenceReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
    private FuzzConversationModel _conversationModel;
    
    private String _fuzzMethod = "GET";
    private String _fuzzUrl = "http://localhost:8080/test";
    private String _fuzzVersion = "HTTP/1.0";
    
    private List _fuzzHeaders = new ArrayList();
    private List _fuzzParameters = new ArrayList();
    private List _fuzzSources = new ArrayList();
    private List _parameterPriorities = new ArrayList();
    
    private int _maxPriority = 0;
    private int _requestIndex = 0;
    private int _totalRequests = 0;
    
    private boolean _busyFuzzing = false;
    
    
    /** Creates a new instance of FuzzerModel */
    public FuzzerModel(FrameworkModel model) {
        _model = model;
        _conversationModel = new FuzzConversationModel(model);
    }
    
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    public void addConversation(ConversationID id) {
        _conversationModel.addConversation(id);
    }
    
    public void setFuzzMethod(String method) {
        Object old = _fuzzMethod;
        _fuzzMethod = method;
        if (old == null || _fuzzMethod != old)
            _changeSupport.firePropertyChange(PROPERTY_FUZZMETHOD, old,  _fuzzMethod);
        resetFuzzer();
    }
    
    public String getFuzzMethod() {
        return _fuzzMethod;
    }
    
    public void setFuzzUrl(String url) {
        Object old = _fuzzUrl;
        _fuzzUrl = url;
        if (old == null || _fuzzUrl!= old)
            _changeSupport.firePropertyChange(PROPERTY_FUZZURL, old,  _fuzzUrl);
        resetFuzzer();
    }
    
    public String getFuzzUrl() {
        return _fuzzUrl;
    }
    
    public void setFuzzVersion(String version) {
        Object old = _fuzzVersion;
        _fuzzVersion = version;
        if (old == null || _fuzzVersion != old)
            _changeSupport.firePropertyChange(PROPERTY_FUZZVERSION, old,  _fuzzVersion);
        resetFuzzer();
    }
    
    public String getFuzzVersion() {
        return _fuzzVersion;
    }
    
    public void setBusyFuzzing(boolean busy) {
        boolean old = _busyFuzzing;
        _busyFuzzing = busy;
        if (_busyFuzzing!= old)
            _changeSupport.firePropertyChange(PROPERTY_BUSYFUZZING, old,  _busyFuzzing);
    }
    
    public boolean isBusyFuzzing() {
        return _busyFuzzing;
    }
    
    public int getFuzzHeaderCount() {
        return _fuzzHeaders.size();
    }
    
    public void addFuzzHeader(int index, NamedValue header) {
        _fuzzHeaders.add(index, header);
        fireFuzzHeaderAdded(index);
        resetFuzzer();
    }
    
    public void setFuzzHeader(int index, NamedValue header) {
        _fuzzHeaders.set(index, header);
        fireFuzzHeaderChanged(index);
        resetFuzzer();
    }
    
    public void removeFuzzHeader(int index) {
        _fuzzHeaders.remove(index);
        fireFuzzHeaderRemoved(index);
        resetFuzzer();
    }
    
    public NamedValue getFuzzHeader(int position) {
        return (NamedValue) _fuzzHeaders.get(position);
    }
    
    public int getFuzzParameterCount() {
        return _fuzzParameters.size();
    }
    
    public void addFuzzParameter(int index, Parameter parameter, FuzzSource fuzzSource, int priority) {
        _logger.info("Adding a parameter at index " + index);
        _fuzzParameters.add(index, parameter);
        _fuzzSources.add(index, fuzzSource);
        _parameterPriorities.add(index, new Integer(priority));
        fireFuzzParameterAdded(index);
        resetFuzzer();
    }
    
    public void setFuzzParameter(int index, Parameter parameter, FuzzSource fuzzSource, int priority) {
        _logger.info("Setting a parameter at index " + index + ", source is " + fuzzSource);
        _fuzzParameters.set(index, parameter);
        _fuzzSources.set(index, fuzzSource);
        _parameterPriorities.set(index, new Integer(priority));
        fireFuzzParameterChanged(index);
        resetFuzzer();
    }
    
    public void removeFuzzParameter(int index) {
        _logger.info("Removing parameter at index " + index);
        _fuzzParameters.remove(index);
        _fuzzSources.remove(index);
        _parameterPriorities.remove(index);
        fireFuzzParameterRemoved(index);
        resetFuzzer();
    }
    
    public Parameter getFuzzParameter(int index) {
        return (Parameter) _fuzzParameters.get(index);
    }
    
    public FuzzSource getParameterFuzzSource(int index) {
        return (FuzzSource) _fuzzSources.get(index);
    }
    
    public int getFuzzParameterPriority(int index) {
        Integer p = (Integer)_parameterPriorities.get(index);
        if (p == null)
            return 0;
        return p.intValue();
    }
    
    public Object getFuzzParameterValue(int index) {
        FuzzSource fuzzSource = getParameterFuzzSource(index);
        if (fuzzSource != null) {
            return fuzzSource.current();
        } else {
            return ((Parameter)_fuzzParameters.get(index)).getValue();
        }
    }
    
    public void resetFuzzer() {
        Map sizes = new HashMap();
        _maxPriority = 0;
        int count = getFuzzParameterCount();
        for (int i=0; i<count; i++) {
            FuzzSource source = getParameterFuzzSource(i);
            if (source != null) {
                source.reset();
                Integer priority = new Integer(getFuzzParameterPriority(i));
                _maxPriority = Math.max(priority.intValue(), _maxPriority);
                int size = source.size();
                Integer s = (Integer) sizes.get(priority);
                if (s == null) {
                    sizes.put(priority, new Integer(size));
                } else {
                    sizes.put(priority, new Integer(Math.min(s.intValue(),size)));
                }
            }
        }
        int totalsize = 1;
        Iterator it = sizes.values().iterator();
        while (it.hasNext()) {
            Integer size = (Integer) it.next();
            totalsize = totalsize * size.intValue();
        }
        setRequestIndex(0);
        setTotalRequests(totalsize);
        _conversationModel.clear();
    }
    
    public boolean incrementFuzzer() {
        boolean success = false;
        int count = getFuzzParameterCount();
        for (int priority=0; priority<=_maxPriority; priority++) {
            // make sure we can increment ALL the sources at the current priority
            // set success = true if so
            for (int param=0; param<count; param++) {
                FuzzSource source = getParameterFuzzSource(param);
                if (source == null) continue; // nothing to do for this param
                int paramPriority = getFuzzParameterPriority(param);
                if (paramPriority == priority) { // we need to increment this one
                    if (source.hasNext()) {
                        source.increment();
                        success = true;
                    } else {
                        success = false;
                        break;
                    }
                }
            }
            if (success) {
                setRequestIndex(getRequestIndex()+1);
                return true;
            } else {
                // no success, reset all parameters <= current priority, we'll
                // go around again, and increment the next priority level
                for (int param=0; param<count; param++) {
                    FuzzSource source = getParameterFuzzSource(param);
                    if (source == null) continue; // nothing to do for this param
                    int paramPriority = getFuzzParameterPriority(param);
                    if (paramPriority <= priority) {
                        source.reset();
                    }
                }
            }
        }
        // we have gone through all the permutations, no more to do
        setRequestIndex(getTotalRequests());
        return false;
    }
    
    private void setRequestIndex(int index) {
        int old = _requestIndex;
        _requestIndex = index;
        if (_requestIndex != old)
            _changeSupport.firePropertyChange(PROPERTY_REQUESTINDEX, old,  _requestIndex);
    }
    
    public int getRequestIndex() {
        return _requestIndex;
    }
    
    private void setTotalRequests(int count) {
        int old = _totalRequests;
        _totalRequests = count;
        if (_totalRequests != old)
            _changeSupport.firePropertyChange(PROPERTY_TOTALREQUESTS, old,  _totalRequests);
    }
    
    public int getTotalRequests() {
        return _totalRequests;
    }
    
    public void addSignature(Signature signature) {
        HttpUrl url = signature.getUrl();
        _model.addUrlProperty(url, "SIGNATURE", signature.toString());
    }
    
    public int getSignatureCount(HttpUrl url) {
        String[] signatures = _model.getUrlProperties(url, "SIGNATURE");
        if (signatures == null) return 0;
        return signatures.length;
    }
    
    public Signature getSignature(HttpUrl url, int index) {
        String[] signatures = _model.getUrlProperties(url, "SIGNATURE");
        if (signatures == null) return null;
        try {
            return new Signature(signatures[index]);
        } catch (MalformedURLException mue) {
            _logger.severe("Malformed URL reading a signature! " + mue.getMessage());
            return null;
        }
    }
    
    public void addChecksum(HttpUrl url, String checksum) {
        _model.addUrlProperty(url, "CHECKSUM", checksum);
    }
    
    public int getChecksumCount(HttpUrl url) {
        String[] checksums = _model.getUrlProperties(url, "CHECKSUM");
        if (checksums == null) return 0;
        return checksums.length;
    }
    
    public String getChecksum(HttpUrl url, int index) {
        String[] checksums = _model.getUrlProperties(url, "CHECKSUM");
        if (checksums == null) return null;
        return checksums[index];
    }
    
    public void addModelListener(FuzzerListener listener) {
        _listenerList.add(FuzzerListener.class, listener);
    }
    
    public void removeModelListener(FuzzerListener listener) {
        _listenerList.remove(FuzzerListener.class, listener);
    }
    
    /**
     * tells listeners that a header has been added
     * @param url the url
     */
    protected void fireFuzzHeaderAdded(int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.FUZZHEADER_ADDED, index);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).fuzzHeaderAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a header has been removed
     * @param url the url
     */
    protected void fireFuzzHeaderChanged(int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.FUZZHEADER_CHANGED, index);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).fuzzHeaderChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a header has been removed
     * @param url the url
     */
    protected void fireFuzzHeaderRemoved(int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.FUZZHEADER_REMOVED, index);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).fuzzHeaderRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a parameter has been added
     * @param url the url
     */
    protected void fireFuzzParameterAdded(int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.FUZZPARAMETER_ADDED, index);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).fuzzParameterAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a parameter has been added
     * @param url the url
     */
    protected void fireFuzzParameterChanged(int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.FUZZPARAMETER_CHANGED, index);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).fuzzParameterChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a parameter has been added
     * @param url the url
     */
    protected void fireFuzzParameterRemoved(int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FuzzerEvent evt = new FuzzerEvent(this, FuzzerEvent.FUZZPARAMETER_REMOVED, index);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FuzzerListener.class) {
                try {
                    ((FuzzerListener)listeners[i+1]).fuzzParameterRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    private class FuzzConversationModel extends AbstractConversationModel {
        
        private List _conversations = new ArrayList();
        
        public FuzzConversationModel(FrameworkModel model) {
            super(model);
        }
        
        void addConversation(ConversationID id) {
            try {
                _rwl.writeLock().acquire();
                int index = _conversations.size();
                _conversations.add(id);
                _rwl.readLock().acquire();
                _rwl.writeLock().release();
                fireConversationAdded(id, index);
                _rwl.readLock().release();
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
            }
        }
        
        void clear() {
            try {
                _rwl.writeLock().acquire();
                int index = _conversations.size();
                _conversations.clear();
                _rwl.readLock().acquire();
                _rwl.writeLock().release();
                fireConversationsChanged();
                _rwl.readLock().release();
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
            }
        }
        
        public ConversationID getConversationAt(int index) {
            return (ConversationID) _conversations.get(index);
        }

        public int getIndexOfConversation(ConversationID id) {
            return _conversations.indexOf(id);
        }

        public Sync readLock() {
            return _rwl.readLock();
        }

        public int getConversationCount() {
            return _conversations.size();
        }
        
    }
}
