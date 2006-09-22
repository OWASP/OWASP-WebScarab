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
import java.util.Set;
import java.util.HashSet;
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

    private Set testedURLandParameterpairs = new HashSet();
    
    private String xssTestString = "><script>a=/XSS BUG/; alert(a.source)</script>";
    private String crlfTestString = "%0d%0aWebscarabXSSCRLFTest:%20OK%0d%0a";
    private String crlfInjectedHeader="WebscarabXSSCRLFTest";
    
    /** Creates a new instance of ExtensionsModel */
    public XSSCRLFModel(FrameworkModel model) {
        _model = model;
        /*
         * lower table with possibly vulnerable URLs
         */
        _conversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
            public boolean shouldFilter(ConversationID id) {
                return !isXSSVulnerable(id) && !isCRLFVulnerable(id);                
            }
        };
        
        /*
         * upper table with suspected URLs             
         */
        _suspectedConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
            public boolean shouldFilter(ConversationID id) {
                return !isCRLFSuspected(id) && !isXSSSuspected(id);
            }
        };
    }
    
    public ConversationModel getVulnerableConversationModel() {
        return _conversationModel;
    }
    
    public ConversationModel getSuspectedConversationModel() {
        return _suspectedConversationModel;
    }           
    
    public void markAsXSSSuspicious(ConversationID id, HttpUrl url, String location, String parameter) {
        _model.addConversationProperty(id, "XSS-" + location, parameter);
        _model.addUrlProperty(url, "XSS-" + location, parameter);
    }
    
    public void markAsCRLFSuspicious(ConversationID id, HttpUrl url, String location, String parameter) {
        _model.addConversationProperty(id, "CRLF-" + location, parameter);
        _model.addUrlProperty(url, "CRLF-" + location, parameter);
    }
    
    public boolean isXSSSuspected(ConversationID id) {
        boolean suspect = false;
        suspect |= (_model.getConversationProperty(id, "XSS-GET") != null);
        suspect |= (_model.getConversationProperty(id, "XSS-POST") != null);
        return suspect;
    }
    
    public boolean isCRLFSuspected(ConversationID id) {
        boolean suspect = false;
        suspect |= (_model.getConversationProperty(id, "CRLF-GET") != null);
        suspect |= (_model.getConversationProperty(id, "CRLF-POST") != null);
        return suspect;
    }
    
    public boolean isSuspected(HttpUrl url) {
        boolean suspect = false;
        suspect |= (_model.getUrlProperty(url, "XSS-GET") != null);
        suspect |= (_model.getUrlProperty(url, "XSS-POST") != null);
        suspect |= (_model.getUrlProperty(url, "CRLF-GET") != null);
        suspect |= (_model.getUrlProperty(url, "CRLF-POST") != null);
        return suspect;
    }
    
    public void setCRLFVulnerable(ConversationID id, HttpUrl url) {
        _model.setUrlProperty(url, "CRLF", "TRUE");
        _model.setConversationProperty(id, "CRLF", "TRUE");
    }
    
    public boolean isCRLFVulnerable(ConversationID id) {
        return "TRUE".equals(_model.getConversationProperty(id, "CRLF"));
    }
    
    public boolean isCRLFVulnerable(HttpUrl url) {
        return "TRUE".equals(_model.getUrlProperty(url, "CRLF"));
    }
    
    public void setXSSVulnerable(ConversationID id, HttpUrl url) {
        _model.setUrlProperty(url, "XSS", "TRUE");
        _model.setConversationProperty(id, "XSS", "TRUE");
    }
    
    public boolean isXSSVulnerable(ConversationID id) {
        return "TRUE".equals(_model.getConversationProperty(id, "XSS"));
    }
    
    public boolean isXSSVulnerable(HttpUrl url) {
        return "TRUE".equals(_model.getUrlProperty(url, "XSS"));
    }
    
    public String[] getCRLFSuspiciousParameters(ConversationID id, String where) {
        return _model.getConversationProperties(id, "CRLF-"+where);
    }
    
    public String[] getXSSSuspiciousParameters(ConversationID id, String where) {
        return _model.getConversationProperties(id, "XSS-"+where);
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

    private boolean isTested(Request req, String vulnParam) {
        HttpUrl url = req.getURL();
        return testedURLandParameterpairs.contains(url.getSHPP()+vulnParam);
    }

    public void enqueueRequest(Request req, String paramName) {
        synchronized(toBeAnalyzedQueue) {
            if (!isTested(req, paramName)) {
                toBeAnalyzedQueue.addLast(req);
                toBeAnalyzedQueue.notifyAll();
                testedURLandParameterpairs.add(req.getURL().getSHPP()+paramName);
            }
        }
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
