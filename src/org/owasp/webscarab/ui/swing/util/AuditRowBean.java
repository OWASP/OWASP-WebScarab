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
/*
 * AuditRowBean.java
 *
 * Created on 30 June 2002, 15:09
 */

package org.owasp.webscarab.ui.swing.util;

import java.beans.*;
import org.owasp.webscarab.data.*;
import java.net.URL;

/**
 *
 * @author  thp
 * @version 
 * Bean representation of the AuditRow - hides the type checking
 * and may allow for range etc checking.
 */
public class AuditRowBean extends Object implements java.io.Serializable {
    AuditRow _row = null;
    public AuditRowBean(AuditRow r){
        _row = r;
    }
   /**
    *	private static final Class[] _t = { Integer.class, Integer.class, Integer.class, URL.class, 
		String.class, DbListener.class, Integer.class, Integer.class, Map.class, Integer.class };
	private static final String[] _n = { "suiteid",  // id for attack suite
	"attackid",  // id for single attack
	"vulnid",  // id for vulnerability description
	"target",  // the URL (with port) to be attacked
	"attackmodule",  // the java class that performs the attack
	"owner",  // one of spider, analyse, attack, output
	"status",  // run|susp|stop|done
	"result",  // success | failure
	"resultargs",  // data collected by attackmodule like credent.
	"severeness" // severeness of the attack
	};
    */
    public Integer getAttackId(){
        return (Integer) _row.get("attackid");
    }
    public Integer getVulnId(){
        return (Integer) _row.get("vulnid");
    }
    public URL getTarget(){
        return (URL) _row.get(3);
    }
    public String getAttackModule(){
        return (String) _row.get("attackmodule");
    }
    public DbListener getOwner(){
        return ((DbListener) _row.get("owner"));
    }
    // etc...
}
