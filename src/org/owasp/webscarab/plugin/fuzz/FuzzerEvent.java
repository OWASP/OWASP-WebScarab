/*
 * FuzzerEvent.java
 *
 * Created on 11 March 2005, 10:51
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.model.SiteModelEvent;
import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rogan
 */
public class FuzzerEvent extends SiteModelEvent {
    
    public static int URL_APPSTATUS_CHANGED = 101;
    public static int URL_POTENTIAL_APPSTATUS_CHANGED = 102;
    public static int URL_SIGNATURE_ADDED = 103;
    
    public static int URL_AUTHENTICATION_REQUIRED = 104;
    public static int URL_ERROR = 105;
    
    /** Creates a new instance of FuzzerEvent */
    public FuzzerEvent(Object source, int eventType, HttpUrl url) {
        super(source, eventType, url, null);
    }
    
}
