/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * AsyncFetcher.java
 *
 * Created on August 6, 2003, 8:03 PM
 */

package org.owasp.webscarab.httpclient;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import java.util.logging.Logger;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class AsyncFetcher {
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private Fetcher[] _fetchers;
    private boolean[] _pending;
    
    public AsyncFetcher(String basename, int threads) {
        _fetchers = new Fetcher[threads];
        _pending = new boolean[threads];
        for (int i=0; i<threads; i++) {
            _fetchers[i] = new Fetcher(basename + "-" + i);
            _fetchers[i].start();
            _pending[i] = false;
        }
        // give the threads a chance to start, and wait()
        Thread.yield();
    }
    
    public boolean hasCapacity() {
        for (int i=0; i<_fetchers.length; i++) {
            if (_fetchers[i].hasCapacity()) return true;
        }
        return false;
    }
    
    public boolean submit(Request request) {
        for (int i=0; i<_fetchers.length; i++) {
            if (_fetchers[i].hasCapacity()) {
                _fetchers[i].submit(request);
                return true;
            }
        }
        return false;
    }
    
    public boolean hasResponse() {
        for (int i=0; i<_fetchers.length; i++) {
            if (_fetchers[i].hasResponse()) return true;
        }
        return false;
    }
    
    public Response receive() throws IOException {
        for (int i=0; i<_fetchers.length; i++) {
            if (_fetchers[i].hasResponse()) {
                return _fetchers[i].receive();
            }
        }
        _logger.info("receive called, but no response available");
        return null;
    }
    
    public boolean isBusy() {
        for (int i=0; i<_fetchers.length; i++) {
            if (_fetchers[i].isBusy()) return true;
        }
        return false;
    }
    
    public void stop() {
        for (int i=0; i<_fetchers.length; i++) {
            _fetchers[i].interrupt();
        }
    }
    
    private class Fetcher extends Thread {
        
        private HTTPClient _hc = HTTPClientFactory.getInstance().getHTTPClient();
        private Request _request = null;
        private Response _response = null;
        private IOException _error = null;
        private boolean _occupied = false;
        private boolean _busy = false;
        
        public Fetcher(String name) {
            super(name);
            setDaemon(true);
        }
        
        public synchronized boolean hasCapacity() {
            return ! _occupied;
        }
        
        public void submit(Request request) {
            synchronized (this) {
                _request = request;
                _response = null;
                _error = null;
                _occupied = true;
                _busy = true;
                this.notifyAll();
                // System.out.println("Notifying!");
            }
            Thread.yield();
        }
        
        public void run() {
            try {
                while (true) {
                    synchronized (this) {
                        this.wait();
                    }
                    // System.out.println("Got notified");
                    Response response = null;
                    try {
                        response = _hc.fetchResponse(_request);
                        response.flushContentStream();
                    } catch (IOException ioe) {
                        _error = ioe;
                        _response = null;
                    }
                    synchronized (this) {
                        _response = response;
                        _busy = false;
                        this.notifyAll();
                    }
                }
            } catch (InterruptedException ie) {}
        }
        
        public synchronized boolean hasResponse() {
            return _occupied && (_response != null || _error != null);
        }
        
        public synchronized Response receive() throws IOException {
            if (_request != null && ! hasResponse()) {
                try {
                    _logger.warning("Receive called before hasResponse returns true! Expect a deadlock!");
                    this.wait();
                } catch (InterruptedException ie) {}
            }
            
            _occupied = false;
            if (_error != null) throw _error;
            return _response;
        }
        
        public synchronized boolean isBusy() {
            return _busy;
        }
        
    }
    
}