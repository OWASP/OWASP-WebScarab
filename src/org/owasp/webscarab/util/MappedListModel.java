/*
 * MappedListModel.java
 *
 * Created on August 6, 2003, 9:00 PM
 */

package org.owasp.webscarab.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Collection;
import java.util.Set;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.swing.AbstractListModel;

/**
 *
 * @author  rdawes
 */
public class MappedListModel extends AbstractListModel implements Map {
    
    private List _list = new ArrayList();
    private Map _map = new TreeMap();
    
    /** Creates a new instance of SequencedTreeMap */
    public MappedListModel() {
    }
    
    public void clear() {
        int size = _list.size();
        _list.clear();
        _map.clear();
        fireIntervalRemoved(this, 0, size);
    }
    
    public Object put(Object key, Object value) {
        if (! _map.containsKey(key)) {
            _list.add(key);
            Object obj = _map.put(key,value);
            fireIntervalAdded(this, _list.size(), _list.size());
            return obj;
        }
        return _map.put(key, value);
    }
    
    public void putAll(java.util.Map map) {
        throw new UnsupportedOperationException("putall has not been implemented yet!");
    }
    
    public Object remove(Object key) {
        if (_map.containsKey(key)) {
            int index = _list.indexOf(key);
            _list.remove(index);
            Object obj = _map.remove(key);
            fireIntervalRemoved(this, index, index);
            return obj;
        }
        return null;
    }
    
    public Object remove(int index) {
        Object key = _list.remove(index);
        Object obj = _map.remove(key);
        fireIntervalRemoved(this, index, index);
        return obj;
    }
    
    public int indexOf(Object elem) {
        return _list.indexOf(elem);
    }
    
    public Object get(int index) {
        return _map.get(_list.get(index));
    }
    
    public Set keySet() {
        return Collections.unmodifiableSet(_map.keySet());
    }
    
    public Collection values() {
        return Collections.unmodifiableCollection(_map.values());
    }
    
    public Set entrySet() {
        return Collections.unmodifiableSet(_map.entrySet());
    }
        
    public boolean containsKey(Object key) {
        return _map.containsKey(key);
    }
    
    public boolean containsValue(Object value) {
        return _map.containsValue(value);
    }
    
    public Object get(Object key) {
        return _map.get(key);
    }
    
    public boolean isEmpty() {
        return _map.isEmpty();
    }
    
    public int size() {
        return _map.size();
    }
    
    public Object getElementAt(int index) {
        return get(index);
    }
    
    public int getSize() {
        return _list.size();
    }
    
}
