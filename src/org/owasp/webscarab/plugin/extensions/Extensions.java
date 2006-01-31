/*
 * Extensions.java
 *
 * meder: Plugin to check for common extensions of files (temporary files
 * backup files and directory archives)
 *
 * Created on 04 December 2005, 08:52
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.extensions;

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.net.MalformedURLException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.extensions.ExtensionsModel;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.httpclient.FetcherQueue;
import org.owasp.webscarab.httpclient.ConversationHandler;
import org.owasp.webscarab.model.UrlModel;

/**
 *
 * @author rdawes
 */
public class Extensions implements Plugin, ConversationHandler {
    
    public static final int MAXLINKS = 100;
    
    private Framework _framework;
    private ExtensionsModel _model;
    private Logger _logger = Logger.getLogger(getClass().getName());
    private Thread _runThread;
    private FetcherQueue _fetcherQueue = null;
    private int _threads = 4;
    private int _delay = 100;
    
    /** Creates a new instance of Extensions */
    public Extensions(Framework framework) {
        _framework = framework;
        _model = new ExtensionsModel(framework.getModel());
        try {
            String property = "WebScarab.extensions.threads";
            String threads = Preferences.getPreference(property, "4");
            _threads = Integer.parseInt(threads);
            property = "WebScarab.extensions.delay";
            String delay = Preferences.getPreference(property, "100");
            _delay = Integer.parseInt(delay);
        } catch (NumberFormatException nfe) {
            _threads = 4;
            _delay = 100;
        }
    }

    public void analyse(ConversationID id, Request request, Response response, String origin) {              

    }

    public void flush() throws StoreException {
    }

    public String getPluginName() {
        return "Extensions";
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
        _model.setRunning(true);
        Request newReq;
        HttpUrl origUrl;
        Response resp;
        HttpUrl url;

        _model.setStatus("Started");
        _model.setStopping(false);
        _runThread = Thread.currentThread();

        // start the fetchers
        _fetcherQueue = new FetcherQueue(getPluginName(), this, _threads, _delay);

        //try {
            _model.setRunning(true);
            while (!_model.isStopping()) {
                origUrl = _model.dequeueURL();                
                if (origUrl == null) {                    
                    continue;
                }
                String[] exts;
                if (origUrl.getPath().endsWith("/")) {
                    exts = _model.getDirectoryExtensions();
                    if (origUrl.getPath().length() < 2) {
                        continue;
                    }
                } else {
                    exts = _model.getFileExtensions();                    
                }
                
                for (int ix = 0; ix < exts.length; ix++) {
                    _model.incrementExtensionsTested(origUrl);
                    newReq = newRequest(origUrl, exts[ix]);
                    _fetcherQueue.submit(newReq);
                }                
            }          
        //}
        _fetcherQueue.clearRequestQueue();
        _fetcherQueue.stop();
        _model.setRunning(false);
        _runThread = null;
        _model.setStatus("Stopped");
    }
    
    public void responseReceived(Response response) {
        
        if (response.getStatus().equalsIgnoreCase("200")) {
            _framework.addConversation(response.getRequest(), response, getPluginName());
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
    
    public synchronized String[] loadStrings(File file) throws IOException {
        List strings = new ArrayList();
        String line;
        
        BufferedReader input = new BufferedReader(new FileReader(file));
        
        while ((line = input.readLine()) != null) {
            strings.add(line);
        }
        
        return (String[])strings.toArray(new String[0]);
    }
        
    public ExtensionsModel getModel() {
        return _model;
    }
    
    public void checkExtensionsUnder(HttpUrl url) throws IOException {
        List links = new LinkedList();        
        
        queueLinksUnder(url, links, MAXLINKS);        
        while (links.size() > 0) _model.enqueueURL((HttpUrl)links.remove(0));        
    }
    
    private void queueLinksUnder(HttpUrl url, List links, int max) {
                
        if (!_model.isTested(url)) {
            links.add(url);
        }
        if (links.size() == max) return;
        
        UrlModel urlModel = _model.getUrlModel();        
        int count = urlModel.getChildCount(url);
        for (int i=0; i<count; i++) {
            HttpUrl child = urlModel.getChildAt(url, i);
            queueLinksUnder(child, links, max);
            if (links.size() == max) return;
        }
    }
        
    
    public void checkExtensionsFor(HttpUrl urls[]) throws IOException {
        // I select a bunch of URL's, click check THESE
        for (int ix=0; ix < urls.length; ix++) {
                _model.enqueueURL(urls[ix]);
        }
    }
    
    public void stopChecks() {
        // Stop checks, let the other thread return ASAP
        System.out.println("stopChecks()");
    }
    
    public Request newRequest(HttpUrl url, String ext) {
        Request req = new Request();
        String path = url.getPath();
        
        try {
            
            req.setMethod("GET");
            req.setVersion("HTTP/1.0");
            if (url.getPath().endsWith("/")) {
                path = url.getPath();
                path = path.substring(0, path.length() - 1);
            }
            req.setURL(new HttpUrl(url.getScheme() + "://" + url.getHost() + ":" + url.getPort() + path + ext));                
            req.setHeader("Host", url.getHost() + ":" + url.getPort());
            req.setHeader("Connection", "Close");
        }
        catch (java.net.MalformedURLException e) {
            return null;
        }
        /*
        NamedValue[] headers = _model.getExtraHeaders();        
        if (headers != null && headers.length > 0) {
            for (int i=0; i< headers.length; i++) {
                if (headers[i] != null)
                    req.addHeader(headers[i]);
            }
        }
        */
        return req;        
    }
    
}
