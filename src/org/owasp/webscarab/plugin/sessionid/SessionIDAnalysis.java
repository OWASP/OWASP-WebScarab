/*
 * SessionidAnalysis.java
 *
 * Created on 16 November 2003, 05:19
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.httpclient.AsyncFetcher;
import org.owasp.webscarab.httpclient.URLFetcher;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.URLInfo;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.WebScarabPlugin;
import org.owasp.webscarab.util.Util;

import org.owasp.webscarab.util.NotifiableListModel;
import javax.swing.ListModel;

import java.io.IOException;

import java.util.Vector;
import java.util.Date;
import java.util.TreeMap;
import java.util.Iterator;
import java.net.URL;
import java.math.BigInteger;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 *
 * @author  rdawes
 */
public class SessionIDAnalysis implements WebScarabPlugin, Runnable {
    
    private Plug _plug;
    
    public static final int LOCATION_COOKIE = 0;
    public static final int LOCATION_URL = 1;
    public static final int LOCATION_BODY = 2;
    
    private NotifiableListModel _idNames = new NotifiableListModel();
    private TreeMap _idLists = new TreeMap();
    private TreeMap _calculatorCache = new TreeMap();
    
    private AsyncFetcher[] _fetchers;
    private int _threads = 4;
    private Vector _requestQueue = new Vector();
    private Vector _responseQueue = new Vector();
    
    private int _location = 0;
    private String _name = null;
    private String _regex = null;
    private Request _request = null;
    private int _count = 0;
    
    private SessionIDStore _store = null;
    
    private Thread _calcThread = null;
    
    private static final int MAXLENGTH=1000; // the longest cookie we will analyse
    
    /** Creates a new instance of SessionidAnalysis */
    public SessionIDAnalysis(Plug plug) {
        _plug = plug;
        Thread me = new Thread(this);
        me.setDaemon(true);
        me.setPriority(Thread.MIN_PRIORITY);
        me.setName("SessionID Analysis");
        me.start();
        System.err.println("SessionID initialised");
        new Timer(true).schedule(new TimerTask() {
            public void run() {
                if (_request != null && _count > 0) { // if we have a request to fetch, and there are some outstanding
                    if (_requestQueue.size() == 0) {
                        _requestQueue.add(_request);
                        _count--; // maybe decrement the counter when we get a sessionid from the response?
                    }
                }
            }
        }, 10000, 100); // wait 10 seconds to initialise, then every tenth of a second
    }
    
    public void run() {
        _fetchers = new AsyncFetcher[_threads];
        for (int i=0; i<_threads; i++) {
            _fetchers[i] = new AsyncFetcher(_requestQueue, _responseQueue, "SessionID-" + i);
        }
        Request request;
        Response response;
        while (true) {
            // see if there are any responses waiting for us
            try {
                synchronized (_responseQueue) {
                    while (_responseQueue.size()>0) {
                        response = (Response) _responseQueue.remove(0);
                        if (response != null) {
                            SessionID sessid = getIDfromResponse(response, _location, _name, _regex);
                            if (sessid != null) {
                                addSessionID(_name, sessid);
                            }
                        }
                    }
                }
                try {
                    Thread.currentThread().sleep(100);
                } catch (InterruptedException ie) {}
            } catch (ArrayIndexOutOfBoundsException aioob) {
                try {
                    Thread.currentThread().sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
    }

    public SessionID getIDfromResponse(Response response, int location, String name, String regex) {
        Request request = response.getRequest();
        if (request == null) {
            System.out.println("Request was null?");
            return null;
        }
        URL url = request.getURL();
        String dateString = response.getHeader("Date");
        Date date;
        if (dateString != null) {
            date = Util.rfc822(dateString);
        } else {
            date = new Date();
        }
        SessionID sessid = null;
        Pattern pattern = Pattern.compile(regex);
        if (location==LOCATION_COOKIE) {
            String[][] headers = response.getHeaders();
            for (int i=0; i<headers.length; i++) {
                if (headers[i][0].equals("Set-Cookie")) {
                    Cookie cookie = new Cookie(date, url, headers[i][1]);
                    if (cookie.getKey().equals(name)) {
                        String value = cookie.getValue();
                        Matcher matcher = pattern.matcher(value);
                        if (matcher.matches() && matcher.groupCount()>=1) {
                            value = matcher.group(1);
                        }
                        return new SessionID(date, value);
                    }
                }
            }
        } else if (location == LOCATION_BODY) {
            String content = new String(response.getContent());
            if (content.equals("")) {
                return null;
            }
            Matcher matcher = pattern.matcher(content);
            if (matcher.matches() && matcher.groupCount()>=1) {
                return new SessionID(date, matcher.group(1));
            }
            return null;
        }
        System.out.println("Didn't get an id?");
        return null;
    }
    
    private void addSessionID(String name, SessionID id) {
        NotifiableListModel list;
        synchronized (_idLists) {
            list = (NotifiableListModel) _idLists.get(name);
            if (list == null) {
                list = new NotifiableListModel();
                _idLists.put(name, list);
                _idNames.addElement(name);
            }
        }
        int size = list.size();
        if (size==0) {
            list.addElement(id);
            return;
        }
        SessionID last = (SessionID) list.lastElement();
        if (id.getDate().equals(last.getDate()) || id.getDate().after(last.getDate())) {
            list.addElement(id);
            return;
        }
        for (int i=size-1; i>=0; i--) {
            SessionID sess = (SessionID) list.get(i);
            if (id.getDate().before(sess.getDate())) {
                list.insertElementAt(id, i);
                return;
            }
        }
        System.err.println("Fell off the end adding a sessionid!");
    }
    
    public Response fetchResponse(Request request) throws IOException {
        return new URLFetcher().fetchResponse(request);
    }
    
    public ListModel getSessionIDs(final Request request, int location, String name, String regex, int count) {
        synchronized(_requestQueue) {
            _requestQueue.clear();
        }
        if (name == null || name.equals("")) {
            return null;
        }
        NotifiableListModel list;
        synchronized (_idLists) {
            list = (NotifiableListModel) _idLists.get(name);
            if (list == null) {
                list = new NotifiableListModel();
                _idLists.put(name, list);
                _idNames.addElement(name);
            }
        }
        _location = location;
        _name = name;
        _regex = regex;
        _request = request;
        _count = count;
        return list;
    }
    
    public ListModel getSessionIDNames() {
        return _idNames;
    }
    
    public ListModel getSessionIDList(String name) {
        return (ListModel) _idLists.get(name);
    }
    
    public void calculate(final String name) {
        SessionIDCalculator calc = (SessionIDCalculator) _calculatorCache.get(name);
        if (calc == null) {
            NotifiableListModel nlm = (NotifiableListModel) _idLists.get(name);
            calc = new SessionIDCalculator(nlm);
            _calculatorCache.put(name, calc);
        }
        final SessionIDCalculator theCalculator = calc;
        if (_calcThread == null || !_calcThread.isAlive()) {
            _calcThread = new Thread(new Runnable() {
                public void run() {
                    theCalculator.calculate();
                }
            }, "Calculation");
            _calcThread.setDaemon(true);
            _calcThread.setPriority(Thread.MIN_PRIORITY);
            _calcThread.start();
        } else {
            System.err.println("Calculator is active");
        }
    }
    
    public void analyse(Request request, Response response, Conversation conversation, URLInfo urlinfo, Object parsed) {
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Session ID Analysis");
    }
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @throws StoreException if there is any problem saving the session data
     *
     */
    public void saveSessionData() throws StoreException {
        if (_store != null) {
            _store.writeSessionIDs(_idLists);
        }
    }
    
    /** Configures a session store for the plugin to use to save any persistent data.
     * The Plugin defines the interface for the store, the store implements the
     * interfaces of each plugin, so that it can be cast to each type in each plugin.
     * This allows us to define the methods that the plugin needs to save its data,
     * without specifying how or where that data is saved. That detail is implemented
     * in a concrete implementation of the various interfaces.
     * The plugin is expected to read any existing data from the store as part of this
     * method, or at any other time that the plugin prefers
     * @param store Store is an object that implements the interface specified by each plugin
     * @throws StoreException if there are any problems reading the existing data out of the store
     *
     */
    public void setSessionStore(Object store) throws StoreException {
        if (store != null && store instanceof SessionIDStore) {
            _store = (SessionIDStore) store;
            synchronized (_idLists) {
                _idLists.clear(); // this fires its own events
                _idNames.clear();
                TreeMap map = _store.readSessionIDs();
                if (map == null || map.size() == 0) {
                    return;
                }
                Iterator it = map.keySet().iterator();
                while (it.hasNext()) {
                    String name = (String) it.next();
                    _idLists.put(name, map.get(name));
                    _idNames.addElement(name);
                }
            }
        } else {
            throw new StoreException("object passed does not implement SessionIDStore!");
        }
    }
    
}
