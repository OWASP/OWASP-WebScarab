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
 * Link.java
 *
 * Created on August 7, 2003, 10:28 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rdawes
 */
public class Link {
    
    private HttpUrl _url;
    private String _referer;
    
    /** Creates a new instance of Link */
    public Link(HttpUrl url, String referer) {
        _url = url;
        _referer = referer;
    }
    
    public HttpUrl getURL() {
        return _url;
    }
    
    public String getReferer() {
        return _referer;
    }
    
    public String toString() {
        return _url.toString() + " via " + _referer;
    }
}
