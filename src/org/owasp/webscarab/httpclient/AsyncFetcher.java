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

import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class AsyncFetcher implements Runnable {

    private Vector _requestQueue;
    private Vector _responseQueue;
    private URLFetcher _uf = new URLFetcher();
    private Logger _logger = Logger.getLogger("AsyncFetcher");
    
    /** Creates a new instance of AsyncFetcher */
    public AsyncFetcher(Vector requestQueue, Vector responseQueue) {
        _requestQueue = requestQueue;
        _responseQueue = responseQueue;
        Thread me = new Thread(this);
        me.setDaemon(true);
        me.start();
    }
    
    public void run() {
        Request request;
        Response response;
        while (true) {
            try {
                request = (Request) _requestQueue.remove(0);
                if (request != null) {
                    response = _uf.fetchResponse(request);
                    InputStream cs = response.getContentStream();
                    if (cs != null) {
                        response.readContentStream();
                    }
                    _responseQueue.add(response);
                }
            } catch (ArrayIndexOutOfBoundsException aioob) {
                try {
                    Thread.currentThread().sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
    }
    
}
