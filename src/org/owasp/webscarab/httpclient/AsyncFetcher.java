/*
 * AsyncFetcher.java
 *
 * Created on August 6, 2003, 8:03 PM
 */

package org.owasp.webscarab.httpclient;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import java.util.Vector;
import java.lang.ArrayIndexOutOfBoundsException;

import java.util.logging.Logger;

import java.lang.Runnable;
import java.lang.Thread;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class AsyncFetcher implements Runnable {
    
    private boolean _stopping = false;
    private boolean _stopped = false;
    
    private Vector _requestQueue;
    private Vector _responseQueue;
    private HTTPClient _hc = HTTPClientFactory.getInstance().getHTTPClient();
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    public AsyncFetcher(Vector requestQueue, Vector responseQueue) {
        _requestQueue = requestQueue;
        _responseQueue = responseQueue;
    }
    
    public void run() {
        Request request;
        Response response;
        
        _stopping = false;
        _stopped = false;
        
        while (! _stopping) {
            synchronized(_requestQueue) {
                if (_requestQueue.size()>0) {
                    request = (Request) _requestQueue.remove(0);
                } else {
                    request = null;
                }
            }
            if (request != null) {
                try {
                    response = _hc.fetchResponse(request);
                    response.flushContentStream();
                    _responseQueue.add(response);
                } catch (IOException ioe) {
                    _logger.severe("IOException fetching " + request.getURL().toString() + " : " + ioe);
                }
            } else {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
        _stopped = true;
    }
    
    public boolean stop() {
        _stopping = true;
        if (!_stopped) {
            for (int i=0; i<20; i++) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {}
                if (_stopped) {
                    return true;
                }
            }
            return false;
        } else {
            return true;
        }
    }
    
}
