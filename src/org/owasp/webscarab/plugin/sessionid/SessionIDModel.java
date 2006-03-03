/*
 * SessionIDModel.java
 *
 * Created on 29 April 2005, 08:00
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.plugin.AbstractPluginModel;

import java.util.Map;
import java.util.TreeMap;

import java.math.BigInteger;
import java.util.logging.Logger;

import javax.swing.event.EventListenerList;

/**
 *
 * @author  rogan
 */
public class SessionIDModel extends AbstractPluginModel {
    
    private FrameworkModel _model;
    private SessionIDStore _store = null;
    
    private Map _sessionIDs = new TreeMap();
    private Map _calculators = new TreeMap();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private EventListenerList _listenerList = new EventListenerList();
    
    /** Creates a new instance of SessionIDModel */
    public SessionIDModel(FrameworkModel model) {
        _model = model;
    }
    
    public ConversationModel getConversationModel() {
        return _model.getConversationModel();
    }
    
    public void setStore(SessionIDStore store) throws StoreException {
        _calculators.clear();
        _store = store;
        for (int i=0; i<_store.getSessionIDNameCount(); i++) {
            String key = _store.getSessionIDName(i);
            Calculator calc = new DefaultCalculator();
            _calculators.put(key, calc);
            for (int j=0; j<_store.getSessionIDCount(key); j++) {
                calc.add(_store.getSessionIDAt(key, j));
            }
        }
        fireSessionIDsChanged();
        setModified(false);
    }
    
    public void setCalculator(String key, Calculator calc) {
        _calculators.put(key, calc);
        calc.reset();
        synchronized(_store) {
            int count = _store.getSessionIDCount(key);
            for (int i=0; i<count; i++) {
                calc.add(_store.getSessionIDAt(key, i));
            }
        }
        fireCalculatorChanged(key);
    }
    
    public void addSessionID(String key, SessionID id) {
        setModified(true);
        int insert = _store.addSessionID(key, id);
        Calculator calc = (Calculator) _calculators.get(key);
        if (calc == null) {
            calc = new DefaultCalculator();
            _calculators.put(key, calc);
        }
        boolean changed = calc.add(id);
        fireSessionIDAdded(key, insert);
        if (changed) fireCalculatorChanged(key);
    }
    
    public void clearSessionIDs(String key) {
        setModified(true);
        _store.clearSessionIDs(key);
        _calculators.remove(key);
        fireSessionIDsChanged();
    }
    
    public int getSessionIDNameCount() {
        if (_store == null) return 0;
        return _store.getSessionIDNameCount();
    }
    
    public String getSessionIDName(int index) {
        return _store.getSessionIDName(index);
    }
    
    public int getSessionIDCount(String key) {
        return _store.getSessionIDCount(key);
    }
    
    public SessionID getSessionIDAt(String key, int index) {
        return _store.getSessionIDAt(key, index);
    }
    
    public BigInteger getSessionIDValue(String key, SessionID id) {
        Calculator calc = (Calculator) _calculators.get(key);
        if (calc == null) return null;
        return calc.calculate(id);
    }
    
    public BigInteger getMinimumValue(String key) {
        Calculator calc = (Calculator) _calculators.get(key);
        if (calc == null) return null;
        return calc.min();
    }
    
    public BigInteger getMaximumValue(String key) {
        Calculator calc = (Calculator) _calculators.get(key);
        if (calc == null) return null;
        return calc.max();
    }
    
    public Request getRequest(ConversationID id) {
        return _model.getRequest(id);
    }
    
    public void addRequestCookie(ConversationID id, String cookie) {
        _model.addConversationProperty(id, "COOKIE", cookie);
        // FIXME: fireCookieAdded here
    }
    
    public void addResponseCookie(ConversationID id, HttpUrl url, Cookie cookie) {
        _model.addConversationProperty(id, "SET-COOKIE", cookie.getName() + "=" + cookie.getValue());
        _model.addUrlProperty(url, "SET-COOKIE", cookie.getName());
        // FIXME: fireSetCookieAdded here
    }
    
    public String getRequestCookies(ConversationID id) {
        return _model.getConversationProperty(id, "COOKIE");
    }
    
    public String getResponseCookies(ConversationID id) {
        return _model.getConversationProperty(id, "SET-COOKIE");
    }
    
    public String getResponseCookies(HttpUrl url) {
        return _model.getUrlProperty(url, "SET-COOKIE");
    }
    
    public void flush() throws StoreException {
        if (_store != null && isModified()) _store.flush();
        setModified(false);
    }
    
    public void addModelListener(SessionIDListener listener) {
        _listenerList.add(SessionIDListener.class, listener);
    }
    
    public void removeModelListener(SessionIDListener listener) {
        _listenerList.remove(SessionIDListener.class, listener);
    }
    
    protected void fireSessionIDAdded(String key, int index) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SessionIDListener.class) {
                try {
                    ((SessionIDListener)listeners[i+1]).sessionIDAdded(key, index);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }

    protected void fireCalculatorChanged(String key) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SessionIDListener.class) {
                try {
                    ((SessionIDListener)listeners[i+1]).calculatorChanged(key);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }

    protected void fireSessionIDsChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SessionIDListener.class) {
                try {
                    ((SessionIDListener)listeners[i+1]).sessionIDsChanged();
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }

}
