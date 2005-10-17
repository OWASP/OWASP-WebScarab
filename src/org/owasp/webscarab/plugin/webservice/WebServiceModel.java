/*
 * WebServiceModel.java
 *
 * Created on 06 October 2005, 08:35
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.util.logging.Logger;
import javax.swing.event.EventListenerList;
import javax.wsdl.Definition;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.AbstractPluginModel;

/**
 *
 * @author rdawes
 */
public class WebServiceModel extends AbstractPluginModel {
    
    private FrameworkModel _model;
    private ConversationModel _wsdlModel;
    
    private Definition _definition = null;
    private Schema _schema = null;
    
    private ServiceInfo[] _services;
    
    private NamedValue[] _extraHeaders = null;
    
    private EventListenerList _listenerList = new EventListenerList();
    
    private Logger _logger = Logger.getLogger(getClass().toString());
    
    /** Creates a new instance of WebServiceModel */
    public WebServiceModel(FrameworkModel model) {
        _model = model;
        _wsdlModel = new WSDLConversationModel(model);
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void addModelListener(WebServiceListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(WebServiceListener.class, listener);
        }
    }
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    public void removeModelListener(WebServiceListener listener) {
        synchronized(_listenerList) {
            _listenerList.remove(WebServiceListener.class, listener);
        }
    }
    
    public byte[] getWSDL(ConversationID id) {
        Response response = _model.getResponse(id);
        byte[] content = response.getContent();
        if (content != null)
            return content;
        return null;
    }
    
    public HttpUrl getURL(ConversationID id) {
        return _model.getRequestUrl(id);
    }
    
    public void setSchema(Schema schema) {
        _schema = schema;
    }
    
    public Schema getSchema() {
        return _schema;
    }
    
    public void setDefinition(Definition definition) {
        _definition = definition;
    }
    
    public Definition getDefinition() {
        return _definition;
    }
    
    private boolean isWSDLResponse(ConversationID id) {
        String wsdl = _model.getConversationProperty(id, "WSDL");
        if (wsdl != null && wsdl.equals("true"))
            return true;
        return false;
    }
    
    public void setWSDLResponse(ConversationID id) {
        _model.setConversationProperty(id, "WSDL", "true");
    }
    
    public void setServices(ServiceInfo[] services) {
        _services = services;
        fireServicesChanged();
    }
    
    public int getServiceCount() {
        return _services == null ? 0 : _services.length;
    }
    
    public ServiceInfo getServiceInfo(int index) {
        return _services[index];
    }
    
    public ConversationModel getWSDLConversations() {
        return _wsdlModel;
    }
    
    public void setExtraHeaders(NamedValue[] headers) {
        _extraHeaders = headers;
    }
    
    public NamedValue[] getExtraHeaders() {
        return _extraHeaders;
    }
    
    /**
     * notifies listeners that all cookies in the model have changed
     */
    protected void fireServicesChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==WebServiceListener.class) {
                try {
                    ((WebServiceListener)listeners[i+1]).servicesChanged();
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e + " at " + e.getStackTrace()[1]);
                }
            }
        }
    }
    
    private class WSDLConversationModel extends FilteredConversationModel {
        
        public WSDLConversationModel(FrameworkModel model) {
            super(model, model.getConversationModel());
        }
        
        public boolean shouldFilter(ConversationID id) {
            return ! isWSDLResponse(id);
        }
        
    }
}
