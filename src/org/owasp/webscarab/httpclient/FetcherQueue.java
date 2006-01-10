/*
 * FetcherQueue.java
 *
 * Created on 10 January 2006, 05:49
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.httpclient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;



/**
 *
 * @author rdawes
 */
public class FetcherQueue {
    
    private ConversationHandler _handler;
    
    private Fetcher[] _fetchers;
    private int _requestPerSecond;
    private List _requestQueue = new ArrayList();
    private boolean _running = true;
    
    /** Creates a new instance of FetcherQueue */
    public FetcherQueue(ConversationHandler handler, int threads, int requestsPerSecond) {
        _handler = handler;
        _fetchers = new Fetcher[threads];
        _requestPerSecond = requestsPerSecond;
        for (int i=0; i<threads; i++) {
            _fetchers[i] = new Fetcher();
        }
        start();
    }
    
    public void stop() {
        _running = false;
    }
    
    public void start() {
        _running = true;
        for (int i=0; i<_fetchers.length; i++) {
            _fetchers[i].start();
        }
        
    }
    public void submit(Request request) {
        synchronized (_requestQueue) {
            _requestQueue.add(request);
            _requestQueue.notify();
        }
    }
    
    public int getRequestsQueued() {
        synchronized (_requestQueue) {
            return _requestQueue.size();
        }
    }
    
    private void responseReceived(Response response) {
        _handler.responseReceived(response);
    }
    
    private void requestError(Request request, IOException ioe) {
        _handler.requestError(request, ioe);
    }
    
    private Request getNextRequest() {
        synchronized (_requestQueue) {
            while (_requestQueue.size() == 0) {
                try {
                    _requestQueue.wait();
                } catch (InterruptedException ie) {
                    // check again
                }
            }
            return (Request) _requestQueue.remove(0);
        }
    }
    
    private class Fetcher extends Thread {
        public Fetcher() {
            setDaemon(true);
            setPriority(Thread.MIN_PRIORITY);
        }
        
        public void run() {
            while (_running) {
                Request request = getNextRequest();
                try {
                    responseReceived(HTTPClientFactory.getInstance().fetchResponse(request));
                } catch (IOException ioe) {
                    requestError(request, ioe);
                }
            }
        }
    }
}
