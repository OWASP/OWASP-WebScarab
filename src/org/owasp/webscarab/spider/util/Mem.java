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
package org.owasp.webscarab.spider.util;

public abstract class Mem {

    public static long free () {
        return Runtime.getRuntime ().freeMemory ();
    }

    public static long used () {
        Runtime r = Runtime.getRuntime ();
        return r.totalMemory() - r.freeMemory ();
    }

    public static long total () {
        return Runtime.getRuntime ().totalMemory ();
    }

    public static void report () {
        System.err.println ("Memory: used " + (used()/1000) + "KB, free "
            + (free()/1000) + "KB, total " + (total()/1000) + "KB");
    }

    public static void verbosegc () {
        System.err.println ("Garbage collecting");
        Runtime r = Runtime.getRuntime ();
        r.runFinalization ();
        r.gc ();
        report ();
    }

    public static void dumpThreadInfo () {
        ThreadGroup g = Thread.currentThread().getThreadGroup ();
        Thread[] t = new Thread[g.activeCount ()];
        g.enumerate (t);
        System.err.println ("Active threads in " + g);
        for (int i=0; i<t.length; ++i)
            System.err.println (t[i]);
    }

}
