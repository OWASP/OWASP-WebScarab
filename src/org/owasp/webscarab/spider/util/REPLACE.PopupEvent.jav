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

public class PopupEvent {

    int id; // one of YES (or OK), NO, CANCEL (from PopupDialog)
    String text;

    public PopupEvent (int id, String text) {
        this.id = id;
        this.text = text;
    }

    public int getID () { return id; }
    public String getText () { return text; }
}
