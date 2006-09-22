/*
 * XSSCRLF.java
 *------------------------------------------------------------------------------
 * TODO:
 * - Add ability to detect stored XSS;
 * - Add POST parameters to the ones being tested;
 *------------------------------------------------------------------------------
 *
 * Created on 23 Апрель 2006 г., 16:51
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.xsscrlf;


import java.io.File;
import java.io.IOException;
import java.io.FileReader;
import java.util.logging.Logger;
import java.util.List;
import java.util.ArrayList;
import java.io.BufferedReader;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.httpclient.FetcherQueue;
import org.owasp.webscarab.httpclient.ConversationHandler;
import org.owasp.webscarab.plugin.xsscrlf.XSSCRLFModel;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.util.Encoding;
import java.util.logging.Logger;
import org.owasp.webscarab.httpclient.FetcherQueue;
import java.net.MalformedURLException;

/**
 *
 * @author meder
 */
public class XSSCRLF implements Plugin, ConversationHandler {
    
    private Framework _framework;
    private XSSCRLFModel _model;
    private Logger _logger = Logger.getLogger(getClass().getName());
    private Thread _runThread;
    private FetcherQueue _fetcherQueue = null;
    private int _threads = 4;
    private int _delay = 100;
    public static int MINLENGTH=3;
    
    
    /** Creates a new instance of XSSCRLF */
    public XSSCRLF(Framework framework) {
        _framework = framework;
        _model = new XSSCRLFModel(framework.getModel());        
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {   
        HttpUrl url = request.getURL();
        
        if (_framework.getModel().getConversationOrigin(id).equals(getPluginName())) return;
        
        // is this something we should check?
        String contentType = response.getHeader("Content-Type");
        if (contentType == null) return;
        if (!contentType.matches("text/.*") && !contentType.equals("application/x-javascript")) return;
        byte[] responseContent = response.getContent();
        if ((responseContent == null || responseContent.length == 0) && !response.getStatus().startsWith("3")) return;
        
        // prepare the response body, and headers
        String responseBody = null;
        if (responseContent != null)
            responseBody = new String(responseContent).toUpperCase();
        NamedValue[] headers = response.getHeaders();
        NamedValue[] ucHeaders = new NamedValue[headers.length];
        for (int i=0; i<headers.length; i++) {
            ucHeaders[i] = new NamedValue(headers[i].getName().toUpperCase(), headers[i].getValue().toUpperCase());
        }
        
        String queryString = request.getURL().getQuery();
        if (queryString != null && queryString.length() > 0) {
            NamedValue[] params = NamedValue.splitNamedValues(queryString, "&", "=");
            checkParams(id, url, params, "GET", ucHeaders, responseBody);
        }
        
        if (request.getMethod().equals("POST")) {
            contentType = request.getHeader("Content-Type");
            if ("application/x-www-form-urlencoded".equals(contentType)) {
                byte[] requestContent = request.getContent();
                if (requestContent != null && requestContent.length>0) {
                    String requestBody = new String(requestContent);
                    NamedValue[] params = NamedValue.splitNamedValues(requestBody, "&", "=");
                    checkParams(id, url, params, "POST", ucHeaders, responseBody);
                }
            }
        }
    }

    private void checkParams(ConversationID id, HttpUrl url, NamedValue[] params, String paramLocation, NamedValue[] headers, String body) {
        if (params == null) return;
        for (int i=0; i<params.length; i++) {
            String value = params[i].getValue().toUpperCase();
            if (value.length() >= MINLENGTH) {
                if (isInHeaders(value, headers)) {
                    _model.markAsCRLFSuspicious(id, url, paramLocation, params[i].getName());
                }
                if (body != null && body.indexOf(value) > -1) {
                    _model.markAsXSSSuspicious(id, url, paramLocation, params[i].getName());
                }
            }
        }
    }
    
    /**
     * Checks headers (header name and header value) for the presence of the expression.
     * @param expression the expression to look for.
     * @param headers the array of header name/value pairs.
     */ 
    private boolean isInHeaders(String expression, NamedValue[] headers) {

        if (expression.length() < MINLENGTH) return false;
        expression = Encoding.urlDecode(expression.toUpperCase());
        
        for (int i=0; i < headers.length; i++) {
            if (headers[i].getValue().toUpperCase().indexOf(expression) != -1 ||
                headers[i].getName().toUpperCase().indexOf(expression) != -1) return true;
        }
        return false;
    }
    
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "XSS/CRLF";
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
    public String getStatus() {
        return _model.getStatus();
    }
    
    public boolean isBusy() {
        return _model.isBusy();
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public void run() {
        Request req;
        _model.setRunning(true);
        
        _model.setStatus("Started");
        _model.setStopping(false);
        _runThread = Thread.currentThread();
        // start the fetchers
        _fetcherQueue = new FetcherQueue(getPluginName(), this, _threads, _delay);
        _model.setRunning(true);

        while (!_model.isStopping()) {
            req = _model.dequeueRequest();                
            if (req != null) {
                _fetcherQueue.submit(req);
            }
        }
        _model.setRunning(false);
        _model.setStatus("Stopped");
    }
    
    public void responseReceived(Response response) {
        String body = new String(response.getContent());
        
        ConversationID id = null;
        if (body != null && body.length() >= _model.getXSSTestString().length() &&
                body.indexOf(_model.getXSSTestString()) != -1) {
            _logger.info("XSS - Possibly Vulnerable: " + response.getRequest().getURL());
            id = _framework.addConversation(response.getRequest(), response, getPluginName());
            _model.setXSSVulnerable(id, response.getRequest().getURL());
        }
        if (response.getHeader(_model.getCRLFInjectedHeader()) != null) {
            _logger.info("CRFL - Possibly Vulnerable: " + response.getRequest().getURL());
            if (id == null)
                id = _framework.addConversation(response.getRequest(), response, getPluginName());
            _model.setCRLFVulnerable(id, response.getRequest().getURL());
        }

    }
    
    
    public void requestError(Request request, IOException ioe) {

    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
    }
    
    public boolean stop() {
        _model.setRunning(false);
        return _model.isRunning();
    }
    
    
    public XSSCRLFModel getModel() {
        return _model;
    }
    
    public void stopChecks() {
        // Stop checks, let the other thread return ASAP
        System.out.println("stopChecks()");
    }
    
    public synchronized String loadString(File file) throws IOException {
        StringBuffer buf = new StringBuffer();
        String line;
        
        BufferedReader input = new BufferedReader(new FileReader(file));
        
        while ((line = input.readLine()) != null) {
            buf.append(line);
        }
        
        return buf.toString();
    }    
    
    public void checkSelected (ConversationID []ids) {
        Request req;
        for (int j=0; j < ids.length; j++) {
            req = _model.getRequest(ids[j]);
            checkConversation(ids[j], req, "GET");
            checkConversation(ids[j], req, "POST");
        }
    }
    
    private void checkConversation(ConversationID id, Request req, String where) {
        String[] params = _model.getCRLFSuspiciousParameters(id, where);
        if (params != null && params.length>0) {
            for (int i=0; i<params.length; i++) {
                _logger.info("Testing for CRLF - Conversation ID: "+id+" Parameter:" + params[i]);
                submitCRLFTest(req, where, params[i]);
            }
        }
        params = _model.getXSSSuspiciousParameters(id, where);
        if (params != null && params.length>0) {
            for (int i=0; i<params.length; i++) {
                _logger.info("Testing for XSS - Conversation ID: "+id+" Parameter:" + params[i]);
                submitXSSTest(req, "GET", params[i]);
            }
        }
    }
    
    private void submitXSSTest(Request origReq, String where, String param) {
        String testString = Encoding.urlEncode(_model.getXSSTestString());
        Request req = new Request(origReq);        
        req.setURL(getURLwithTestString(req.getURL(), param, testString));
        _model.enqueueRequest(req, param);
    }
    
    private void submitCRLFTest(Request origReq, String where, String param) {
        String testString = _model.getCRLFTestString();
        Request req = new Request(origReq);
        req.setURL(getURLwithTestString(req.getURL(), param, testString));
        _model.enqueueRequest(req, param);
    }

    private HttpUrl getURLwithTestString(HttpUrl url, String name, String value) {
        StringBuffer buf = new StringBuffer("?");
        
        String querystring = url.getQuery();        
        if (querystring == null) return null;        
        
        NamedValue[] params = NamedValue.splitNamedValues(querystring, "&", "=");        
        for (int i=0; i < params.length; i++) {
            if (params[i].getName().equals(name)) {
                buf.append(params[i].getName() + "=" + value);
            } else {
                buf.append(params[i].getName() + "=" + params[i].getValue());
            }
            if (i < params.length-1) buf.append("&");
        }
        
        try {
            return new HttpUrl(url.getSHPP() + buf.toString());
        } catch (MalformedURLException e) {
            _logger.info("Exception: "+e);
            return null;
        }
    }
    
 
}
