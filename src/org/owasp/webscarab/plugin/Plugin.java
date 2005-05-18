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
 * WebScarabPlugin.java
 *
 * Created on July 10, 2003, 12:21 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 * This abstract class lists the basics that a WebScarab plugin will need to provide
 * @author rdawes
 */
public interface Plugin extends Runnable {
    
    /** The plugin name
     * @return The name of the plugin
     */    
    String getPluginName();
    
    /**
     * informs the plugin that the Session has changed
     * @param model the new model
     */    
    void setSession(String type, Object store, String session) throws StoreException;
    
    /**
     * starts the plugin running
     */
    void run();
    
    boolean isRunning();
    
    /** called to test whether the plugin is able to be stopped
     * @return false if the plugin can be stopped
     */
    boolean isBusy();
    
    /** called to determine what the current status of the plugin is
     */
    String getStatus();
    
    /**
     * called to suspend or stop the plugin
     */
    boolean stop();
    
    /** called to determine whether the data stored within the plugin has been modified
     * and should be saved
     */
    boolean isModified();
    
    /**
     * called to instruct the plugin to flush any memory-only state to the store.
     * @throws StoreException if there is any problem saving the session data
     */    
    void flush() throws StoreException;
    
    void analyse(ConversationID id, Request request, Response response, String origin);
    
    Hook[] getScriptingHooks();
    
    Object getScriptableObject();
    
}
