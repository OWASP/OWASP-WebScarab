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
