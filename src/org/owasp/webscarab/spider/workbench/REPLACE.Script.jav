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
package org.owasp.webscarab.spider.workbench;

import websphinx.*;
import java.io.IOException;
import websphinx.util.PopupDialog;

public class Script implements Action,LinkPredicate,PagePredicate {
    String script;
    boolean asLinkPredicate;

    transient Crawler crawler;
    transient ScriptInterpreter interp;
    transient Object function;

    public Script (String script, boolean asLinkPredicate) {
        this.script = script;
        this.asLinkPredicate = asLinkPredicate;
    }

    public String getScript () {
        return script;
    }

    public boolean equals (Object object) {
        if (! (object instanceof Script))
            return false;
        Script s = (Script)object;
        return s.script.equals (script) 
            && s.asLinkPredicate == asLinkPredicate;
    }    

    static String[] argsLink = {"crawler", "link"};
    static String[] argsPage = {"crawler", "page"};

    public void connected (Crawler crawler) {
        this.crawler = crawler;
        interp = Context.getScriptInterpreter ();
        if (interp != null) {
            try {
                 function = interp.lambda (asLinkPredicate
                                        ? argsLink : argsPage,
                                       script);
            } catch (ScriptException e) {
                PopupDialog.warn (null, "Script Error", e.toString());
                function = null;
            }
        }
    }

    public void disconnected (Crawler crawler) {
         crawler = null;
         interp = null;
         function = null;
    }

    public boolean shouldVisit (Link link) {
        try {
            if (interp == null || function == null)
                // FIX: use GUI to signal error
                throw new ScriptException ("Scripting language is not available");

            Object[] args = new Object[2];
            args[0] = crawler;
            args[1] = link;        
            return toBool (interp.apply (function, args));
        } catch (ScriptException e) {
            System.err.println (e); // FIX: use GUI when available
            return false;
        }
    }

    public boolean shouldActOn (Page page) {
        try {
            if (interp == null || function == null)
                throw new ScriptException ("Scripting language is not available");            

            Object[] args = new Object[2];
            args[0] = crawler;
            args[1] = page;
            return toBool (interp.apply (function, args));
        } catch (ScriptException e) {
            System.err.println (e); // FIX: use GUI when available
            return false;
        }
    }

    public void visit (Page page) {
        try {
            if (interp == null || function == null)
                // FIX: use GUI to signal error
              throw new ScriptException ("Scripting language is not available");

            Object[] args = new Object[2];
            args[0] = crawler;
            args[1] = page;
            interp.apply (function, args);
        } catch (ScriptException e) {
            throw new RuntimeException (e.toString());
        }
    }

    boolean toBool (Object obj) {
        if (! (obj instanceof Boolean))
            return false;
        return ((Boolean)obj).booleanValue();
    }

}
