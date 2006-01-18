/*
 * NullComparator.java
 *
 * Created on 12 January 2006, 05:37
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.util;

import java.util.Comparator;

/**
 *
 * @author rdawes
 */
public class NullComparator implements Comparator {
    
    public NullComparator() {
    }
    
    public int compare(Object o1, Object o2) {
        if (o1 == null && o2 == null) return 0;
        if (o1 == null && o2 != null) return 1;
        if (o1 != null && o2 == null) return -1;
        if (o1 instanceof Comparable) return ((Comparable)o1).compareTo(o2);
        throw new ClassCastException("Incomparable objects " + o1.getClass().getName() + " and " + o2.getClass().getName());
    }
    
}
