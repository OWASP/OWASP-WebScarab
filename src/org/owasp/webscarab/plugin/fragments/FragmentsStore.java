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
    
    int getFragmentTypeCount();
    
    String getFragmentType(int index);
    
    int getFragmentCount(String type);
    
    String getFragmentKeyAt(String type, int position);
    
    int indexOfFragment(String type, String key);
    
    int putFragment(String type, String key, String fragment);
    
    String getFragment(String key);
    
    void flush() throws StoreException;
    
}
