/*
 * ManualEditUI.java
 *
 * Created on August 9, 2004, 3:03 PM
 */

package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  knoppix
 */
public interface ManualEditUI {
    
    Request editRequest(Request request);
    
    Response editResponse(Request request, Response response);
    
}
