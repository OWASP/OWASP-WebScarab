/*
 * SpiderStore.java
 *
 * Created on August 23, 2003, 2:55 PM
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.model.StoreException;
import java.util.TreeMap;

/**
 *
 * @author  rdawes
 */
public interface SessionIDStore {
    
    void writeSessionIDs(TreeMap idmap) throws StoreException;
    
    TreeMap readSessionIDs() throws StoreException;
    
}
