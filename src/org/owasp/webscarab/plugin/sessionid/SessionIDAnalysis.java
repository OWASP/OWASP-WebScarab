/*
 * SessionidAnalysis.java
 *
 * Created on 16 November 2003, 05:19
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.httpclient.AsyncFetcher;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.httpclient.HTTPClientFactory;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.plugin.Plugin;

import java.io.File;
import java.io.IOException;

import java.math.BigInteger;

import java.util.Vector;

import java.util.Date;
import java.util.Map;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Properties;

import java.util.logging.Logger;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.swing.event.EventListenerList;

/**
 *
 * @author  rdawes
 */
public class SessionIDAnalysis extends Plugin {
    
    private SiteModel _model = null;
    
    private Map _sessionIDs = new TreeMap();
    private Map _calculators = new TreeMap();
    
    private AsyncFetcher[] _fetchers;
    private int _threads = 4;
    private Vector _requestQueue;
    private Vector _responseQueue;
    
    private String _name = null;
    private Pattern _regex = null;
    private int _count = 0;
    
    private Request _request = null;
    private Response _response = null;
    
    private SessionIDStore _store = null;
    
    private boolean _stopping = false;
    private Thread _runThread = null;
    
    private HTTPClient _hc = null;
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private SessionIDAnalysisUI _ui = null;
    
    private EventListenerList _listenerList = new EventListenerList();
    
    private String _status = "Stopped";
    
    /** Creates a new instance of SessionidAnalysis */
    public SessionIDAnalysis(Properties props) {
        super(props);
    }
    
    public void setSession(SiteModel model, String storeType, Object connection) throws StoreException {
        // we have no listeners to remove
        _model = model;
        if (storeType.equals("FileSystem") && (connection instanceof File)) {
            _store = new FileSystemStore((File) connection);
        } else {
            throw new StoreException("Store type '" + storeType + "' is not supported in " + getClass().getName());
        }
        _calculators.clear();
        for (int i=0; i<_store.getSessionIDNameCount(); i++) {
            String key = _store.getSessionIDName(i);
            Calculator calc = new DefaultCalculator();
            _calculators.put(key, calc);
            for (int j=0; j<_store.getSessionIDCount(key); j++) {
                calc.add(_store.getSessionIDAt(key, j));
            }
        }
        if (_ui != null) _ui.setModel(model);
    }
    
    public void setUI(SessionIDAnalysisUI ui) {
        _ui = ui;
        if (_ui != null) _ui.setEnabled(_running);
    }
    
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Session ID Analysis");
    }
    
    public void run() {
        _status = "Started";
        _hc = HTTPClientFactory.getInstance().getHTTPClient();
        
        _requestQueue = new Vector();
        _responseQueue = new Vector();
        _fetchers = new AsyncFetcher[_threads];
        for (int i=0; i<_threads; i++) {
            _fetchers[i] = new AsyncFetcher(_requestQueue, _responseQueue);
            Thread thread = new Thread(_fetchers[i]);
            thread.setPriority(Thread.MIN_PRIORITY);
            thread.setDaemon(true);
            thread.setName("SessionID-" + i);
            thread.start();
        }
        
        Timer requestTimer = new Timer(true);
        requestTimer.schedule(new TimerTask() {
            public void run() {
                queueRequest();
            }
        }, 1000, 100); // wait 1 seconds to initialise, then every tenth of a second
        
        _running = true;
        _runThread = Thread.currentThread();
        
        _stopping = false;
        Response response;
        if (_ui != null) _ui.setEnabled(_running);
        while (! _stopping) {
            // see if there are any responses waiting for us
            synchronized (_responseQueue) {
                while (_responseQueue.size()>0) {
                    response = (Response) _responseQueue.remove(0);
                    if (response != null) {
                        Map ids = getIDsFromResponse(response, _name, _regex);
                        Iterator it = ids.keySet().iterator();
                        while (it.hasNext()) {
                            String key = (String) it.next();
                            SessionID id = (SessionID) ids.get(key);
                            addSessionID(key, id);
                        }
                    }
                }
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {}
        }
        requestTimer.cancel();
        _request = null;
        _response = null;
        for (int i=0; i<_threads; i++) {
            _fetchers[i].stop();
        }
        _hc = null;
        _running = false;
        if (_ui != null) _ui.setEnabled(_running);
        _status = "Stopped";
    }
    
    public Map getIDsFromResponse(Response response, String name, Pattern regex) {
        Map ids = new TreeMap();
        Request request = response.getRequest();
        if (request == null) {
            System.out.println("Request was null?");
            return ids;
        }
        HttpUrl url = request.getURL();
        Date date = new Date();
        String[][] headers = response.getHeaders();
        for (int i=0; i<headers.length; i++) {
            if (headers[i][0].equalsIgnoreCase("Set-Cookie")) {
                Cookie cookie = new Cookie(date, url, headers[i][1]);
                SessionID id = new SessionID(date, cookie.getValue());
                ids.put(cookie.getKey(), id);
            }
        }
        if (_name != null && !_name.equals("") && _regex != null) {
            String location = response.getHeader("Location");
            if (location != null) {
                Matcher matcher = regex.matcher(location);
                if (matcher.matches() && matcher.groupCount() > 0) {
                    SessionID id = new SessionID(date, matcher.group(1));
                    ids.put(name, id);
                }
            }
            String type = response.getHeader("Content-Type");
            if (type != null && type.startsWith("text/")) {
                String body = new String(response.getContent());
                Matcher matcher = regex.matcher(body);
                if (matcher.matches() && matcher.groupCount() > 0) {
                    SessionID id = new SessionID(date, matcher.group(1));
                    ids.put(name, id);
                }
            }
        }
        return ids;
    }
    
    public void fetch(Request request, String name, Pattern regex, int count) {
        _request = request;
        _name = name;
        _regex = regex;
        _count = count;
    }
    
    private void queueRequest() {
        if (_request != null && _count > 0) { // if we have a request to fetch, and there are some outstanding
            if (_requestQueue.size() == 0) {
                _requestQueue.add(_request);
                _count--; // maybe decrement the counter when we get a sessionid from the response?
            }
        }
    }
    
    public void setRequest(Request request) {
        _request = request;
    }
    
    public void fetchResponse() throws IOException {
        _response = _hc.fetchResponse(_request);
    }
    
    public Response getResponse() {
        return _response;
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
        if (_ui != null) _ui.calculatorChanged(key);
    }
    
    private void addSessionID(String key, SessionID id) {
        int insert = _store.addSessionID(key, id);
        Calculator calc = (Calculator) _calculators.get(key);
        if (calc == null) {
            calc = new DefaultCalculator();
            _calculators.put(key, calc);
        }
        boolean changed = false;
        changed = calc.add(id);
        if (_ui != null) {
            _ui.sessionIDAdded(key, insert);
            // FIXME consider firing this on a timer to limit recalculations
            if (changed) _ui.calculatorChanged(key);
        }
    }
    
    public int getSessionIDNameCount() {
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
    
    public boolean stop() {
        _stopping = true;
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted!");
        }
        return !_running;
    }
    
    public void flush() throws StoreException {
        if (_store != null) _store.flush();
    }
    
    public boolean isBusy() {
        return _count > 0;
    }
    
    public String getStatus() {
        return _status;
    }
    
}
