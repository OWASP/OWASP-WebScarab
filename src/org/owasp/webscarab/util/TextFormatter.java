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
 * TextFormatter.java
 *
 * Created on April 12, 2004, 6:37 PM
 */

package org.owasp.webscarab.util;

import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.Date;
import java.text.SimpleDateFormat;

/**
 *
 * @author  knoppix
 */
public class TextFormatter extends Formatter {
    
    SimpleDateFormat _sdf = new SimpleDateFormat("HH:mm:ss ");
    
    /** Creates a new instance of TextFormatter */
    public TextFormatter() {
    }
    
    public String format(LogRecord record) {
        StringBuffer buff = new StringBuffer(100);
        buff.append(_sdf.format(new Date(record.getMillis())));
        buff.append(Thread.currentThread().getName());
        String className = record.getSourceClassName();
        if (className.indexOf(".")>-1) { 
            className = className.substring(className.lastIndexOf(".")+1,className.length());
        }
        buff.append("(").append(className).append(".");
        buff.append(record.getSourceMethodName()).append("): ");
        buff.append(record.getMessage());
        if (record.getParameters() != null) {
            Object[] params = record.getParameters();
            buff.append(" { ").append(params[0]);
            for (int i=1; i<params.length; i++) {
                buff.append(", ").append(params[i]);
            }
            buff.append(" }");
        }
        buff.append("\n");
        return buff.toString();
    }
    
}
