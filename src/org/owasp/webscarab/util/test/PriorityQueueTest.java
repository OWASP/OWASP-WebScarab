/*
 * WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University 
 * 
 * This library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library
 * General Public License as published by the Free Software 
 * Foundation, version 2.
 *
 * WebSPHINX homepage: http://www.cs.cmu.edu/~rcm/websphinx/
 */
package org.owasp.webscarab.spider.util.test;

/**
 * SCRATCH, only the testing code scraps from former
 * PriorityQueue imported
 */
public class PriorityQueueTest {

/*    public static void main (String[] args) {
        PriorityQueue q = new PriorityQueue ();

        for (int i=0; i<args.length; ++i) {
            float f = Float.valueOf (args[i]).floatValue();
            q.put (new PQItem (f));
            System.out.println ("put (" + f + ")");
        }

        System.out.println ("getMin() = " + q.getMin());
        System.out.println ("empty() = " + q.empty());

        dump (q);

        if (q.size() > 0) {
            Enumeration enum = q.elements ();
            for (int j=0; j<q.size()/2; ++j)
                enum.nextElement();

            PQItem deletable = (PQItem)enum.nextElement();
            q.delete (deletable);
            System.out.println ("delete (" + deletable + ")");

            dump (q);
        }

        float last = Float.NEGATIVE_INFINITY;
        PQItem item;
        while ((item = (PQItem)q.deleteMin()) != null) {
            System.out.println ("deleteMin() = " + item);
            if (item.getPriority() < last)
                System.out.println ("ERROR! greater than last == " + last);
            last = item.getPriority ();
            dump (q);
        }
    } 
    public static void dump (PriorityQueue q) {
        Enumeration enum = q.elements ();
        for (int j=0; enum.hasMoreElements(); ++j) {
            System.out.println ("elements()[" + (j+1) + "] = " + enum.nextElement());
        }
    } */

/*class PQItem implements Prioritized {
    float priority;

    public PQItem (float priority) {
        this.priority = priority;
    }

    public float getPriority () {
        return priority;
    }

    public String toString () {
        return String.valueOf (priority);
    }
}*/
}
