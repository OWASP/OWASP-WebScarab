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
 * SessionID.java
 *
 * Created on 16 November 2003, 07:29
 */

package org.owasp.webscarab.plugin.sessionid;

import java.util.Date;

/**
 *
 * @author  rdawes
 */
public class SessionID implements Comparable {
    
    private Date _date;
    private String _value;
    
    /** Creates a new instance of SessionID */
    public SessionID(Date date, String value) {
        _date = date;
        _value = value;
    }
    
    public SessionID(String line) {
        int sep = line.indexOf(":");
        String time = line.substring(0, sep);
        _date = new Date(Long.parseLong(time));
        _value = line.substring(sep+2);
    }
    
    public Date getDate() {
        return _date;
    }
    
    public String getValue() {
        return _value;
    }
    
    public int compareTo(Object o) {
        if (o == null) return -1;
        if (!(o instanceof SessionID)) return -1;
        return _date.compareTo(((SessionID)o).getDate());
    }
    
    public String toString() {
        return _date.getTime() + ": " + _value;
    }
    
}
