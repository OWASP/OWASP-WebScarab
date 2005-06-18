/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * Fragments.java
 *
 * Created on August 25, 2004, 10:45 PM
 */

package org.owasp.webscarab.plugin.fragments;

import java.io.File;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.logging.Logger;
import java.util.Date;

import org.htmlparser.nodes.RemarkNode;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.parser.Parser;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.PluginUI;
import org.owasp.webscarab.plugin.Hook;

import org.owasp.webscarab.util.Encoding;

/**
 * This plugin looks for comments and scripts in the source of HTML pages.
 * @author knoppix
 */
public class Fragments implements Plugin {
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private FragmentsModel _model = null;
    private Framework _framework = null;
    
    private FragmentsStore _store = null;
    
    /**
     * Creates a new instance of Fragments
     * @param props contains the user's configuration properties
     */
    public Fragments(Framework framework) {
        _framework = framework;
        _model = new FragmentsModel(framework.getModel());
    }
    
    public FragmentsModel getModel() {
        return _model;
    }
    
    /**
     * Sets the store that this plugin uses
     * @param session the new session
     */    
    public void setSession(String type, Object store, String session) throws StoreException {
        if (type.equals("FileSystem") && (store instanceof File)) {
            _model.setStore(new FileSystemStore((File) store, session));
        } else {
            throw new StoreException("Store type '" + type + "' is not supported in " + getClass().getName());
        }
    }
    
    /**
     * returns the name of the plugin
     * @return the name of the plugin
     */    
    public String getPluginName() {
        return "Fragments";
    }
    
    /**
     * calls the main loop of the plugin
     */
    public void run() {
        _model.setRunning(true);
    }
    
    /**
     * stops the plugin running
     * @return true if the plugin could be stopped within a (unspecified) timeout period, false otherwise
     */    
    public boolean stop() {
        _model.setRunning(false);
        return ! _model.isRunning();
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        HttpUrl url = request.getURL();
        Object parsed = Parser.parse(url, response);
        if (parsed != null && parsed instanceof NodeList) {
            NodeList nodes = (NodeList) parsed;
            try {
                NodeList comments = nodes.searchFor(RemarkNode.class);
                for (NodeIterator ni = comments.elements(); ni.hasMoreNodes(); ) {
                    String fragment = ni.nextNode().toHtml();
                    _model.addFragment(url, id, "COMMENTS", fragment);
                }
                NodeList scripts = nodes.searchFor(ScriptTag.class);
                for (NodeIterator ni = scripts.elements(); ni.hasMoreNodes(); ) {
                    String fragment = ni.nextNode().toHtml();
                    _model.addFragment(url, id, "SCRIPTS", fragment);
                }
            } catch (ParserException pe) {
                _logger.warning("Looking for fragments, got '" + pe + "'");
            }
        }
        
    }
    
    public void flush() throws StoreException {
        _model.flush();
    }
    
    public boolean isBusy() {
        return _model.isBusy();
    }
    
    public String getStatus() {
        return _model.getStatus();
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
}

