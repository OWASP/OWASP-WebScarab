/*
 * HTTPClient.java
 *
 * Created on August 4, 2003, 9:08 AM
 */

package org.owasp.webscarab.httpclient;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public interface HTTPClient {
    
    public Response fetchResponse(Request request);
    
}
