/*
 * CacheMap.java
 *
 * Created on July 15, 2004, 2:59 PM
 */

package org.owasp.webscarab.util;

import java.util.Map;
import java.util.LinkedHashMap;

/**
 * maintains a Most-Recently-Used cache of its entries, up to the max size specified
 * @author knoppix
 */
public class MRUCache extends LinkedHashMap {
    
    private int _maxSize;
    
    /**
     * Creates a new instance of MRUCache, with an initial size of 16, and
     * a load factor of 0.75
     * @param maxSize the maximum size of the cache
     */
    public MRUCache(int maxSize) {
        this(16, maxSize, 0.75f);
    }
    
    /**
     * Creates a new instance of MRUCache, with a load factor of 0.75
     * @param initialCapacity the preferred initial capacity
     * @param maxSize the maximum size of the cache
     */
    public MRUCache(int initialCapacity, int maxSize) {
        this(initialCapacity, maxSize, 0.75f);
    }
    
    /**
     * Creates a new instance of MRUCache
     * @param loadFactor the preferred load factor
     * @param initialCapacity the preferred initial capacity
     * @param maxSize the maximum size of the cache
     */
    public MRUCache(int initialCapacity, int maxSize, float loadFactor) {
        super(initialCapacity, loadFactor, true);
        _maxSize = maxSize;
    }
    
    /**
     * called to determine whether the eldest entry should be removed. Eldest is defined
     * in terms of access order, so a more recently used entry will stay "young"
     * @param eldest the entry
     * @return true if this entry should be removed, false otherwise
     */    
    protected boolean removeEldestEntry(Map.Entry eldest) {
        return size() > _maxSize;
    }
    
}
