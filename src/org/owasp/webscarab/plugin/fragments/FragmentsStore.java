/*
 * FragmentsStore.java
 *
 * Created on August 25, 2004, 11:21 PM
 */

package org.owasp.webscarab.plugin.fragments;

import org.owasp.webscarab.model.StoreException;

/**
 *
 * @author  knoppix
 */
public interface FragmentsStore {

    String putFragment(String content);
    
    String getFragment(String key);
    
    void flush() throws StoreException;
    
}
