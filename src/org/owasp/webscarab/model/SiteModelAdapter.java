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
 * SiteModelAdapter.java
 *
 * Created on September 6, 2004, 5:39 PM
 */

package org.owasp.webscarab.model;

/**
 * provides an adapter between the SiteListener interface and implementations, so that
 * empty methods need not be created
 * @author rogan
 */
public abstract class SiteModelAdapter implements SiteModelListener {
    
    /** Creates a new instance of SiteModelAdapter */
    public SiteModelAdapter() {
    }
    
    /**
     * called after a new conversation has been added to the model
     * @param id the id of the conversation
     */
    public void conversationAdded(SiteModelEvent evt) {}
    
    /**
     * called after a conversation property has been changed
     * @param id the id of the conversation
     * @param property the name of the property that changed
     */
    public void conversationChanged(SiteModelEvent evt) {}
    
    /**
     * called after a conversation has been removed from the model.
     *
     * This is actually not implemented yet, and this method is not called.
     * @param id the ID of the conversation
     * @param position the position in the overall conversation list prior to removal
     * @param urlposition the position in the per-url conversation list prior to removal
     */
    public void conversationRemoved(SiteModelEvent evt) {}
    
    /**
     * called after an Url has been added to the store
     * @param url the url that was added
     */
    public void urlAdded(SiteModelEvent evt) {}
    
    /**
     * called after an Url property has been changed
     * @param url the url that changed
     * @param property the name of the property that changed
     */
    public void urlChanged(SiteModelEvent evt) {}
    
    /**
     * called after an Url has been removed from the model
     * @param url the url that was removed
     * @param position the index of this url under its parent url
     */
    public void urlRemoved(SiteModelEvent evt) {}
    
    /**
     * called after a completely new cookie is added to the model
     * i.e. a new domain, new path, or new cookie name
     * @param cookie the cookie that was added
     */
    public void cookieAdded(SiteModelEvent evt) {}
    
    /**
     * fired after a cookie has been removed from the model. A previous cookie
     * might still exist.
     * @param cookie the cookie that was removed
     */
    public void cookieRemoved(SiteModelEvent evt) {}
    
    /** called after the entire model has changed
     */
    public void dataChanged(SiteModelEvent evt) {}
    
}
