/*
 * AbstractConversationModel.java
 *
 * Created on 13 April 2005, 03:29
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import javax.swing.event.EventListenerList;
import java.util.logging.Logger;
import java.util.Date;

/**
 *
 * @author  rogan
 */
public abstract class AbstractConversationModel implements ConversationModel {
    
    private FrameworkModel _model;
    
    private EventListenerList _listenerList = new EventListenerList();
    
    private Sync _readLock;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of AbstractConversationModel */
    public AbstractConversationModel(FrameworkModel model) {
        _model = model;
    }
    
    public abstract int getConversationCount();
    
    public abstract ConversationID getConversationAt(int index);
    
    public abstract int getIndexOfConversation(ConversationID id);
    
    public abstract Sync readLock();
    
    public String getConversationOrigin(ConversationID id) {
        return _model.getConversationOrigin(id);
    }
    
    public Date getConversationDate(ConversationID id) {
        return _model.getConversationDate(id);
    }
    
    public String getRequestMethod(ConversationID id) {
        return _model.getRequestMethod(id);
    }
    
    public String getResponseStatus(ConversationID id) {
        return _model.getResponseStatus(id);
    }
    
    public HttpUrl getRequestUrl(ConversationID id) {
        return _model.getRequestUrl(id);
    }
    
    public Request getRequest(ConversationID id) {
        return _model.getRequest(id);
    }
    
    public Response getResponse(ConversationID id) {
        return _model.getResponse(id);
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void removeConversationListener(ConversationListener listener) {
        synchronized(_listenerList) {
            _listenerList.remove(ConversationListener.class, listener);
        }
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void addConversationListener(ConversationListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(ConversationListener.class, listener);
        }
    }
    
    /**
     * tells listeners that a new Conversation has been added
     * @param id the conversation
     * @param position the position in the list
     */
    protected void fireConversationAdded(ConversationID id, int position) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        ConversationEvent evt = new ConversationEvent(this, id, position);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ConversationListener.class) {
                try {
                    ((ConversationListener)listeners[i+1]).conversationAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a conversation has been removed, after the fact
     * @param id the conversation ID
     * @param position the position in the overall conversation list prior to removal
     */
    protected void fireConversationRemoved(ConversationID id, int position) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        ConversationEvent evt = new ConversationEvent(this, id, position);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]== ConversationListener.class) {
                try {
                    ((ConversationListener)listeners[i+1]).conversationRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * fired to tell listeners that a particular conversation has had a property change
     * @param id the conversation
     * @param property the name of the property that was changed
     */
    protected void fireConversationChanged(ConversationID id, int position) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        ConversationEvent evt = new ConversationEvent(this, id, position);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ConversationListener.class) {
                try {
                    ((ConversationListener)listeners[i+1]).conversationChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * fired to tell listeners that a particular conversation has had a property change
     * @param id the conversation
     * @param property the name of the property that was changed
     */
    protected void fireConversationsChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ConversationListener.class) {
                try {
                    ((ConversationListener)listeners[i+1]).conversationsChanged();
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
}
