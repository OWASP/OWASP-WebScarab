/*
 * SequencedTreeMap.java
 *
 * Created on August 6, 2003, 9:00 PM
 */

package org.owasp.webscarab.plugin.spider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Collection;
import java.util.Set;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;


/**
 *
 * @author  rdawes
 */
public class SequencedTreeMap extends TreeMap {
    
    private ArrayList _sequence = new ArrayList();
    
    /** Creates a new instance of SequencedTreeMap */
    public SequencedTreeMap() {
    }
    
    public void clear() {
        super.clear();
        _sequence.clear();
    }
    
    public Object put(Object key, Object value) {
        if (! containsKey(key)) {
            _sequence.add(key);
        }
        return super.put(key,value);
    }
    
    public void putAll(java.util.Map map) {
        throw new UnsupportedOperationException("putall has not been implemented yet!");
    }
    
    public Object remove(Object key) {
        if (containsKey(key)) {
            int index = _sequence.indexOf(key);
            _sequence.remove(index);
        }
        return super.remove(key);
    }
    
    public Object remove(int index) {
        Object key = _sequence.remove(index);
        return super.remove(key);
    }
    
    public int indexOf(Object elem) {
        return _sequence.indexOf(elem);
    }
    
    public Object get(int index) {
        return get(_sequence.get(index));
    }
    
    public Set keySet() {
        return Collections.unmodifiableSet(super.keySet());
    }
    
    public Collection values() {
        return Collections.unmodifiableCollection(super.values());
    }
    
    public Set entrySet() {
        return Collections.unmodifiableSet(super.entrySet());
    }
    
    public SortedMap subMap(Object fromKey, Object toKey) {
        return Collections.unmodifiableSortedMap(super.subMap(fromKey, toKey));
    }
    
    public java.util.SortedMap tailMap(Object fromKey) {
        return Collections.unmodifiableSortedMap(super.tailMap(fromKey));
    }
    
    public java.util.SortedMap headMap(Object toKey) {
        return Collections.unmodifiableSortedMap(super.headMap(toKey));
    }
    
}
