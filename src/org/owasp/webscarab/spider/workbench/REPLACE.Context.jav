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

import java.applet.Applet;
import java.applet.AppletContext;

public abstract class Context {

    static Applet applet;
    static String target;
    static AppletContext context;
    static Browser browser;
    static ScriptInterpreter interpreter;

    public static boolean isApplet () {
        return applet != null;
    }

    public static boolean isApplication () {
        return applet == null;
    }

    public static void setApplet (Applet _applet) {
        applet = _applet;
        internalSetApplet ();
    }

    public static void setApplet (Applet _applet, String _target) {
        applet = _applet;
        target = _target;
        internalSetApplet ();
    }

    private static void internalSetApplet () {
        context = applet.getAppletContext ();

        String browserName;
        try {
            browserName = System.getProperty ("browser");
        } catch (Throwable t) {
            browserName = null;
        }

        if (browserName == null) {
            // appletviewer
            browser = null;
            interpreter = null;
        }
        else if (browserName.startsWith ("Netscape")) {
            // Netscape
            Netscape ns = target != null ? new Netscape (context, target) : new Netscape(context, target);
            browser = ns;
            interpreter = ns.getScriptInterpreter ();
        }
        // NIY: Internet Explorer
        else {
            // generic browser
            browser = target != null ? new Browser (context, target) : new Browser (context);
            interpreter = null;
        }
    }

    public static Applet getApplet () {
        return applet;
    }

    public static AppletContext getAppletContext () {
        return context;
    }

    public static Browser getBrowser () {
        return browser;
    }

    public static ScriptInterpreter getScriptInterpreter () {
        return interpreter;
    }
}
