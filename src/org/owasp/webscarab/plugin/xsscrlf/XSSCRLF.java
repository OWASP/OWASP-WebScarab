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
        
        if (checkHeaders(request, response, null)) {
            _model.markAsCRLFSuspicious(url);
        }
        
        if (checkBody(request, response, null)) {
            _model.markAsXSSSuspicious(url);
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
    
    
    /**
     * Checks response for presence of any of the parameters sent in request.
     * @param reqeust the original request
     * @param response the response
     */ 
    private boolean checkHeaders(Request request, Response response, List affectedParams) {        
        boolean retval=false;
        
        // Check GET parameters only
        String querystring = request.getURL().getParameters();        
        if (querystring==null) return false;
        // get rid of '?'
        querystring = querystring.substring(1, querystring.length());
        
        NamedValue[] params = NamedValue.splitNamedValues(querystring, "&", "=");        
        
        for (int i=0; i < params.length; i++) {
            // for now only check for the value
            //if (isInHeaders(params[i].getName(), response.getHeaders()) ||
            if (isInHeaders(params[i].getValue(), response.getHeaders()) ) {
                    retval=true;
                    if (affectedParams != null) {
                        affectedParams.add(params[i]);
                    }
            }
        }
        return retval;
    }

    private boolean checkBody(Request request, Response response, List affectedParams) {
        boolean retval=false;
        
        // Check GET parameters only
        String querystring = request.getURL().getParameters();        
        if (querystring==null) return false;        
        // get rid of '?'
        querystring = querystring.substring(1, querystring.length());        
        NamedValue[] params = NamedValue.splitNamedValues(querystring, "&", "=");
        
        String body = new String(response.getContent()).toUpperCase();
        
        /*
         * XXX meder: maybe need to limit maximum size of the response that is
         * searched
         */
        if (body == null || body.length() < 1 ) return false;
        
        for (int i=0; i < params.length; i++) {
            //if (body.indexOf(Encoding.urlDecode(params[i].getName().toUpperCase())) != -1 ||
            if (body.indexOf(Encoding.urlDecode(params[i].getValue().toUpperCase())) != -1) {
                    retval=true;
                    if (affectedParams != null) {
                        affectedParams.add(params[i]);
                    }
            }            
        }
        return retval;              
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
            if (req == null) {                    
                continue;
            }
            _fetcherQueue.submit(req);
        }
        _model.setRunning(false);
        _model.setStatus("Stopped");
    }
    
    public void responseReceived(Response response) {
        String body = new String(response.getContent());
        
        if (body != null && body.length() >= _model.getXSSTestString().length() &&
                body.indexOf(_model.getXSSTestString()) != -1) {
            _logger.info("XSS - Possibly Vulnerable: " + response.getRequest().getURL());
            _framework.addConversation(response.getRequest(), response, getPluginName());
            _framework.getModel().setUrlProperty(response.getRequest().getURL(), "XSS/CRLF", "XSS");
        }
        if (response.getHeader(_model.getCRLFInjectedHeader()) != null) {
            _logger.info("CRFL - Possibly Vulnerable: " + response.getRequest().getURL());
            _framework.addConversation(response.getRequest(), response, getPluginName());
            _framework.getModel().setUrlProperty(response.getRequest().getURL(), "XSS/CRLF", "CRLF");
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
        Response resp;
        ArrayList affectedParams = new ArrayList();
        
        for (int j=0; j < ids.length; j++) {
            req = _model.getRequest(ids[j]);
            resp = _model.getResponse(ids[j]);
            if (checkHeaders(req, resp, affectedParams)) {
                for (int i=0; i < affectedParams.size(); i++) {
                    _logger.info("Testing for CRLF - Conversation ID: "+ids[j]+" Parameter:" + ((NamedValue)affectedParams.get(i)).getName() + "=" + ((NamedValue)affectedParams.get(i)).getValue());
                    submitCRLFTest(req, resp, (NamedValue)affectedParams.get(i));
                }
            }
            affectedParams.clear();
            if (checkBody(req, resp, affectedParams)) {
                for (int k=0; k < affectedParams.size(); k++) {
                    _logger.info("Testing for XSS - Conversation ID:"+ids[j]+" Parameter: " + ((NamedValue)affectedParams.get(k)).getName() + "=" + ((NamedValue)affectedParams.get(k)).getValue());
                    submitXSSTest(req, resp, (NamedValue)affectedParams.get(k));
                }                
            }
            affectedParams.clear();
        }
    }
    
    private void submitXSSTest(Request origReq, Response resp, NamedValue vulnerableParameter) {
        String testString = Encoding.urlEncode(_model.getXSSTestString());
        Request req = new Request(origReq);        
        req.setURL(getURLwithTestString(req, vulnerableParameter, testString));
        _model.enqueueRequest(req, vulnerableParameter);               
    }
    
    private void submitCRLFTest(Request origReq, Response resp, NamedValue vulnerableParameter) {
        String testString = _model.getCRLFTestString();
        Request req = new Request(origReq);
        req.setURL(getURLwithTestString(req, vulnerableParameter, testString));
        _model.enqueueRequest(req, vulnerableParameter);
    }

    private HttpUrl getURLwithTestString(Request req, NamedValue vulnerableParameter, String testString) {
        StringBuffer buf = new StringBuffer();
        
        /* XXX meder: ugly reconstruction code, can be done better !?
         * HttpUrl should provide easier way
         */
        String querystring = req.getURL().getParameters();        
        if (querystring==null) return null;        
        
        // get rid of '?'        
        querystring = querystring.substring(1, querystring.length());        
        NamedValue[] params = NamedValue.splitNamedValues(querystring, "&", "=");        
        for (int i=0; i < params.length; i++) {
            if (i==0) buf.append("?");            
            if (params[i].getName().equalsIgnoreCase(vulnerableParameter.getName())) {
                buf.append(params[i].getName()+"="+testString);
            } else {
                buf.append(params[i].getName()+"="+params[i].getValue());
            }
            if (i < params.length-1) buf.append("&");
        }
        
        HttpUrl url, oldUrl = req.getURL();
        try {
            url = new HttpUrl(oldUrl.getSHPP()+buf.toString());
        }
        catch (MalformedURLException e) {
            _logger.info("Exception: "+e);
            return null;
        }
        return url;
    }
    
 
}
