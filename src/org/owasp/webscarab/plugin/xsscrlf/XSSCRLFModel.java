/*
 * XSSCRLFModel.java
 *
 * Created on 23 Апрель 2006 г., 16:51
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.xsscrlf;

import java.util.logging.Logger;
import java.util.Hashtable;
import java.util.HashMap;
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
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.AbstractPluginModel;
import org.owasp.webscarab.model.NamedValue;

/**
 *
 * @author meder
 */
public class XSSCRLFModel extends AbstractPluginModel {
    
    private FrameworkModel _model;
    
    private ConversationModel _conversationModel, _suspectedConversationModel;
    
        
    private LinkedList toBeAnalyzedQueue = new LinkedList();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String xssTestString = "><script>a=/XSS BUG/; alert(a.source)</script>";
    private String crlfTestString = "%0d%0aWebscarabXSSCRLFTest:%20OK%0d%0a";
    private String crlfInjectedHeader="WebscarabXSSCRLFTest";
    private HashMap testedURLandParameterpairs = new HashMap();
    
    /** Creates a new instance of ExtensionsModel */
    public XSSCRLFModel(FrameworkModel model) {
        _model = model;
        _conversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
            /*
             * lower table with possibly vulnerable URLs
             */
            public boolean shouldFilter(ConversationID id) {
                return !getConversationOrigin(id).equals("XSS/CRLF");
            }
        };
        
            /*
             * upper table with suspected URLs             
             */
        _suspectedConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
            public boolean shouldFilter(ConversationID id) {
                return getConversationOrigin(id).equals("XSS/CRLF") || !isSuspected(getRequestUrl(id));                
            }
        };
    }
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    public ConversationModel getSuspectedConversationModel() {
        return _suspectedConversationModel;
    }           
    
    public void markAsXSSSuspicious(HttpUrl url) {
        _model.setUrlProperty(url, "XSS/CRLF", "XSS");
    }
    
    public void markAsCRLFSuspicious(HttpUrl url) {
        _model.setUrlProperty(url, "XSS/CRLF", "CRLF");
    }
    
    private boolean isSuspected(HttpUrl url) {
        return _model.getUrlProperty(url, "XSS/CRLF") != null;
    }
    
    public String getXSSTestString() {
        return xssTestString;
    }
    
    public void setXSSTestString(String _xssTestString) {
        xssTestString = _xssTestString;
    }
    
    public String getCRLFTestString() {
        return crlfTestString;        
    }
    
    public void setCRLFTestString(String _crlfTestString) {
        crlfTestString = _crlfTestString;
    }
    
    public String getCRLFInjectedHeader() {
        return crlfInjectedHeader;
    }
    
    public void setCRLFInjectedHeader(String _crlfInjectedHeader) {
        crlfInjectedHeader = _crlfInjectedHeader;
    }
    
    public Request getRequest(ConversationID id) {
        return _model.getRequest(id);
    }
    
    public Response getResponse(ConversationID id) {
        return _model.getResponse(id);
    }

    public void enqueueRequest(Request req, NamedValue vulnParam) {
        synchronized(toBeAnalyzedQueue) {
            if (!isTested(req, vulnParam)) {
                toBeAnalyzedQueue.addLast(req);
                toBeAnalyzedQueue.notifyAll();
                testedURLandParameterpairs.put(req.getURL().getSHPP()+vulnParam.getName(), null);
            }
        }
    }
    
    private boolean isTested(Request req, NamedValue vulnParam) {
        HttpUrl url = req.getURL();        
        return testedURLandParameterpairs.containsKey(url.getSHPP()+vulnParam.getName());
    }
    
    public Request dequeueRequest() {

        synchronized (toBeAnalyzedQueue) {
            try {
                while (toBeAnalyzedQueue.isEmpty()) {
                    toBeAnalyzedQueue.wait();
                }
                return (Request)toBeAnalyzedQueue.removeFirst();
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
