/*
 * SpiderStore.java
 *
 * Created on August 23, 2003, 2:55 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.StoreException;
/**
 *
 * @author  rdawes
 */
public interface SpiderStore {
    
    void writeUnseenLinks(Link[] links) throws StoreException;
    
    Link[] readUnseenLinks() throws StoreException;
    
    void writeSeenLinks(String[] links) throws StoreException;
    
    String[] readSeenLinks() throws StoreException;
    
}
