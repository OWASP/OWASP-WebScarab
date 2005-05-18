/*
 * AbstractConversationModel.java
 *
 * Created on 13 April 2005, 03:29
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import javax.swing.event.EventListenerList;
import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public abstract class AbstractConversationModel implements ConversationModel {
    
    private EventListenerList _listenerList = new EventListenerList();
    
    private Sync _readLock;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of AbstractConversationModel */
    public AbstractConversationModel() {
    }
    
    public abstract int getConversationCount(HttpUrl url);
    
    public abstract ConversationID getConversationAt(HttpUrl url, int index);
    
    public abstract int getIndexOfConversation(HttpUrl url, ConversationID id);
    
    public abstract Sync readLock();
    
    public abstract String getRequestMethod(ConversationID id);
    
    public abstract String getResponseStatus(ConversationID id);
    
    public abstract HttpUrl getRequestUrl(ConversationID id);
    
    public abstract Request getRequest(ConversationID id);
    
    public abstract Response getResponse(ConversationID id);
    
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
