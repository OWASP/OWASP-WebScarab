package org.owasp.webscarab.util.swing;

import org.owasp.webscarab.util.Filter;

import java.util.Arrays;

import javax.swing.ListModel;
import javax.swing.AbstractListModel;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

public class ListFilter extends AbstractListModel {
    
    private int[] _map = new int[0];
    private int _size = 0;
    private int _cap = 10;
    private ListModel _lm = null;
    private Filter _filter = null;
    private FilterChangeListener _fcl = new FilterChangeListener();
    private ListListener _ll = new ListListener();
    
    public ListFilter(ListModel lm, Filter filter) {
        if (lm == null || filter == null) {
            throw new NullPointerException("ListModel and Filter may not be null");
        }
        _lm = lm;
        _filter = filter;
        applyFilter();
        _lm.addListDataListener(_ll);
        _filter.addChangeListener(_fcl);
    }
    
    public void setFilter(Filter filter) {
        if (filter == null) {
            throw new NullPointerException("Filter may not be null");
        }
        synchronized (this) {
            _filter.removeChangeListener(_fcl);
            _filter = filter;
            _filter.addChangeListener(_fcl);
            applyFilter();
        }
    }
    
    private void applyFilter() {
        fireIntervalRemoved(this, 0, _size);
        synchronized (this) {
            int size = _lm.getSize();
            _map = new int[size];
            Arrays.fill(_map, Integer.MAX_VALUE);
            _size = 0;
            for (int i=0; i<size; i++) {
                if (!_filter.filtered(_lm.getElementAt(i))) {
                    _map[_size++] = i;
                }
            }
        }
        fireIntervalAdded(this, 0, _size);
    }
    
    private void delegateIntervalAdded(ListDataEvent e) {
        // count = the number of items added in the underlying list
        int count=e.getIndex1() - e.getIndex0() + 1;
        // size = the number of items added that are unfiltered
        int size=0;
        // map contains the indexes of the unfiltered elements in the underlying listmodel
        int[] map = new int[count];
        // fill with MAX_VALUE so that the search finds the right insertion point
        Arrays.fill(map, Integer.MAX_VALUE);
        // work out which new elements are unfiltered
        // note the <= !
        for (int i=e.getIndex0(); i<=e.getIndex1(); i++) {
            if (!_filter.filtered(_lm.getElementAt(i))) {
                map[size++] = i;
            }
        }
        // insert is the point in _map where any new elements should be inserted
        int insert = Arrays.binarySearch(_map, e.getIndex0());
        if (insert < 0) { // we did not find it exactly
            insert = -insert -1;
        }
        synchronized(this) {
            // shift up the existing indexes after the insertion point to account
            // for the new elements that have been added to the underlying listmodel
            for (int i=insert; i<_size; i++) {
                _map[i] = _map[i]+count;
            }
            if (size == 0) { // there were no new unfiltered items
                return;
            }
            int[] newmap = new int[_lm.getSize()];
            // again, fill with MAX_VALUE so that searches work properly
            Arrays.fill(newmap, Integer.MAX_VALUE);
            // copy the part of the original map up to the insert point
            // copy the new mapped entries
            // copy the remaining items from original map after the insert point
            System.arraycopy(_map, 0, newmap, 0, insert);
            System.arraycopy(map, 0, newmap, insert, size);
            System.arraycopy(_map, insert, newmap, insert+size, _size-insert);
            _map = newmap;
            _size = _size + size;
        }
        // notify outside of the synchronize, since listeners will likely
        // call getElementAt() from the Swing event dispatching thread
        fireIntervalAdded(this, insert, insert+size);
    }
    
    private void delegateIntervalRemoved(ListDataEvent e) {
        // count = the number of items removed from the underlying list
        int count=e.getIndex1() - e.getIndex0() + 1;
        // search for the insertion points of the first and last elements
        int map0 = Arrays.binarySearch(_map, e.getIndex0());
        int map1 = Arrays.binarySearch(_map, e.getIndex1());
        synchronized(this) {
            // adjust the mappings after the last insertion point
            // to account for the elements removed
            // if the insertion point is negative, make it positive
            for (int i=(map1<0 ? -map1-1 : map1); i<_size; i++) {
                _map[i] = _map[i]-count;
            }
            if (map0 < 0 && map0 == map1) {
                // neither end was actually mapped, and there was no range
                return;
            }
            // make both insertion points positive
            if (map0 < 0) {
                map0 = -map0 - 1;
            }
            if (map1 < 0) {
                map1 = -map1 - 1;
            }
            int[] newmap = new int[_lm.getSize()];
            // fill with MAX_VALUE to make searching work
            Arrays.fill(newmap, Integer.MAX_VALUE);
            // copy up to the first "insertion" point
            // copy from the second "insertion" point to the end
            System.arraycopy(_map, 0, newmap, 0, map0);
            System.arraycopy(_map, map1+1, newmap, map0, _size-map1-1);
            _map = newmap;
            _size = _size - (map1 - map0 + 1);
        }
        // notify outside of the synchronize, since listeners will likely
        // call getElementAt() from the Swing event dispatching thread
        fireIntervalRemoved(this, map0, map1);
    }
    
    public Object getElementAt(int index) {
        synchronized (this) {
            return _lm.getElementAt(_map[index]);
        }
    }
    
    public int getSize() {
        synchronized(this) {
            return _size;
        }
    }
    
    public String toString() {
        return listModelToString(this);
    }
    
    private class FilterChangeListener implements ChangeListener {
        
        public void stateChanged(ChangeEvent e) {
            applyFilter();
        }
        
    }
    
    private class ListListener implements ListDataListener {
        
        public void contentsChanged(ListDataEvent e) {
            applyFilter();
        }
        
        public void intervalAdded(ListDataEvent e) {
            delegateIntervalAdded(e);
        }
        
        public void intervalRemoved(ListDataEvent e) {
            delegateIntervalRemoved(e);
        }
        
    }
    
    private static String listModelToString(ListModel lm) {
        StringBuffer buff = new StringBuffer();
        int size = lm.getSize();
        if (size > 0) {
            buff.append(lm.getElementAt(0));
            for (int i=1; i<size; i++) {
                buff.append(", ").append(lm.getElementAt(i));
            }
        }
        return buff.toString();
    }
    
    public static void main(String[] args) {
        Filter f = new Filter() {
            public boolean filtered(Object object) {
                return ((Integer)object).intValue() % 16 != 0;
            }
        };
        
        javax.swing.DefaultListModel lm = new javax.swing.DefaultListModel();
        ListFilter lf = new ListFilter(lm, f);
        for (int i=0; i<32; i++) {
            lm.addElement(new Integer(i));
        }
        for (int i=48; i<64; i++) {
            lm.addElement(new Integer(i));
        }
        System.out.println("Size of the filtered list is: " + lf.getSize());
        System.out.println("Elements are: " + lf);
        lm.addElement(new Integer(64));
        System.out.println("Elements are: " + lf);
        lm.insertElementAt(new Integer(40),32);
        System.out.println("Elements are: " + lf);
        System.err.println("Removing element at 32 = " + lm.getElementAt(32));
        lm.removeElementAt(32);
        System.out.println("Elements are: " + lf);
        System.err.println("Removing element at 31 = " + lm.getElementAt(31));
        lm.removeElementAt(31);
        System.err.println("Underlying model is " + listModelToString(lm));
        System.out.println("Elements are: " + lf);
        for (int i=0; i<9; i++) {
            System.err.println("Removing element at " + i + " = " + lm.getElementAt(i));
            lm.removeElementAt(i);
            System.out.println("Elements are: " + lf);
        }
        System.err.println("\n\n\n");
        System.err.println("Underlying model is " + listModelToString(lm));
        for (int i=0; i<17; i++) {
            System.err.println("Inserting " + (2*i) + " at " + i);
            lm.insertElementAt(new Integer(2*i), i*2);
            System.out.println("Elements are: " + lf);
        }
        System.err.println("Removing " + lm.getElementAt(8) + " to " + lm.getElementAt(16));
        lm.removeRange(8, 16);
        System.err.println("Underlying model is " + listModelToString(lm));
        System.out.println("Elements are: " + lf);
    }
    
    
}

