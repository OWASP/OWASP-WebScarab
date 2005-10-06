/*
 * Compare.java
 *
 * Created on 18 May 2005, 05:33
 */

package org.owasp.webscarab.plugin.compare;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Hook;

import org.owasp.webscarab.util.LevenshteinDistance;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public class Compare implements Plugin {
    
    private CompareModel _model;
    private ConversationID _selected = null;
    private HttpUrl _url = null;
    private Thread _runThread = null;
    private Object _lock = new Object();
    private LevenshteinDistance _diff = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of Compare */
    public Compare(Framework framework) {
        _model = new CompareModel(framework.getModel());
    }
    
    public CompareModel getModel() {
        return _model;
    }
    
    public void setBaseConversation(HttpUrl url, ConversationID id) {
        _model.clearConversations();
        _url = url;
        _selected = id;
        if (_model.isBusy())
            _runThread.interrupt();
        synchronized(_lock) {
            _lock.notifyAll();
        }
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
    }
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "Compare";
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
        _runThread = Thread.currentThread();
        _model.setRunning(true);
        int index = 0;
        int count = 0;
        ConversationID id = null;
        ConversationModel cmodel = _model.getConversationModel();
        while (!_model.isStopping()) {
            try {
                synchronized(_lock) {
                    _lock.wait();
                }
                if (id != _selected) {
                    id = _selected;
                    _model.setBusy(true);
                    Response baseResponse = cmodel.getResponse(id);
                    byte[] baseBytes = baseResponse.getContent();
                    String type = baseResponse.getHeader("Content-Type");
                    if (type == null || !type.startsWith("text")) {
                        _logger.warning("Base response is not text, skipping!");
                        return;
                    }
                    List baseline = tokenize(baseBytes);
                    _diff = new LevenshteinDistance(baseline);
                    
                    count = cmodel.getConversationCount();
                    _logger.info("Checking " + count + " conversaitons");
                    for (int i=0; i<count; i++) {
                        ConversationID cid = cmodel.getConversationAt(i);
                        _logger.info("Checking conversation " + i + " == " + cid);
                        if (cid.equals(id)) {
                            _model.setDistance(cid, 0);
                        } else {
                            Response response = cmodel.getResponse(cid);
                            String ctype = response.getHeader("Content-Type");
                            _logger.info("Content-type is " + ctype);
                            if (ctype != null && ctype.startsWith("text")) {
                                byte[] bytes = response.getContent();
                                List target = tokenize(bytes);
                                _model.setDistance(cid, _diff.getDistance(target));
                            }
                        }
                    }
                    _model.setBusy(false);
                }
                Thread.sleep(100);
            } catch (InterruptedException ie) {}
        }
        _model.setRunning(false);
        _model.setStopping(false);
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
    }
    
    public boolean stop() {
        _model.setStopping(true);
        _runThread.interrupt();
        try {
            Thread.sleep(50);
        } catch (InterruptedException ie) {}
        return ! _model.isRunning();
    }
    
    private List tokenize(byte[] bytes) {
        if (bytes == null)
            return new ArrayList();
//        List byteList = new ArrayList();
//        for (int i=0; i<bytes.length; i++) {
//            byteList.add(new Byte(bytes[i]));
//        }
//        return byteList;
//        
        String[] words = new String(bytes).split("\\s");
        List tokens = Arrays.asList(words);
        return tokens;
    }
    
}
