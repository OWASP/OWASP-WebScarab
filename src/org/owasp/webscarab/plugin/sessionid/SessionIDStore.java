/*
 * SpiderStore.java
 *
 * Created on August 23, 2003, 2:55 PM
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.model.StoreException;

/**
 *
 * @author  rdawes
 */
public interface SessionIDStore {
    
    int addSessionID(String key, SessionID id);
    
    int getSessionIDNameCount();
    
    String getSessionIDName(int index);
    
    int getSessionIDCount(String key);
    
    SessionID getSessionIDAt(String key, int index);
    
    void flush() throws StoreException;
    
}
