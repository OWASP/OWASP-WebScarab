/*
 * Copyright (c) 2002 owasp.org.
 * This file is part of WebScarab.
 * WebScarab is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * WebScarab is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The valid license text for this file can be retrieved with
 * the call:   java -cp owasp.jar org.owasp.webscarab.LICENSE
 * 
 * If you are not able to view the LICENSE that way, which should
 * always be possible within a valid and working WebScarab release,
 * please write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.owasp.webscarab.ui.swing.util;
import org.owasp.webscarab.ui.swing.EventRouter;

/**
 * Provides the basic interface that gui modules implement
 * This allows the event router to treat them all the same (largely)
 * and keeps the actual names of gui objects private.
 *
 * The event router will call _all_ of these on the event thread
 * so the module author does not need to worry about synchronization
 *
 * @author  thp
 * @version 
 */
public interface Module {

    /**
     * Called by object that creates the module
     */
    void setEventRouter(EventRouter evr);
    /**
     * called to set the status text on the bottom line of tab pane
     */
    void setStatusText(String statusLine);
    
    /**
     * called with a row from the database that needs displaying
     */
    void setData(AuditRowBean row);
    
    /**
     *called to set the running/paused status
     */
    void setState(boolean run);
    /**
     * called to set the progress bar
     */
    void setProgress(int percent);
    
}

