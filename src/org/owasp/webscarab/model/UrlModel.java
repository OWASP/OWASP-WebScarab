/*
 * UrlModel.java
 *
 * Created on 13 April 2005, 03:58
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

/**
 *
 * @author  rogan
 */
public interface UrlModel {

    int getChildCount(HttpUrl parent);
    
    HttpUrl getChildAt(HttpUrl parent, int index);
    
    int getIndexOf(HttpUrl url);
    
    Sync readLock();
    
    void addUrlListener(UrlListener listener);
    
    void removeUrlListener(UrlListener listener);
    
}
