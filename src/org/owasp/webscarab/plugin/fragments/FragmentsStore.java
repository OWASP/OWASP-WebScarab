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
 * FragmentsStore.java
 *
 * Created on August 25, 2004, 11:21 PM
 */

package org.owasp.webscarab.plugin.fragments;

import org.owasp.webscarab.model.StoreException;

/**
 *
 * @author  knoppix
 */
public interface FragmentsStore {
    
    int getFragmentTypeCount();
    
    String getFragmentType(int index);
    
    int getFragmentCount(String type);
    
    String getFragmentKeyAt(String type, int position);
    
    int indexOfFragment(String type, String key);
    
    int putFragment(String type, String key, String fragment);
    
    String getFragment(String key);
    
    void flush() throws StoreException;
    
}
