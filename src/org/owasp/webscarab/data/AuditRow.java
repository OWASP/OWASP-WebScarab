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
package org.owasp.webscarab.data;

import java.util.Map;
import java.net.URL;

import org.owasp.data.AbstractArrayRow;

/** 
 * TODO: Description
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public class AuditRow 
	extends AbstractArrayRow 
{

	/** index for suiteid */
	public final static int I_SUITEID = 0;
	/** index for attackid */
	public final static int I_ATTACKID = 1;
	/** index for vulnid */
	public final static int I_VULNID = 2;
	/** index for target URL */
	public final static int I_TARGET = 3; 
	/** index for attack module */
	public final static int I_MODULE = 4;
	/** index for row owner */
	public final static int I_OWNER = 5;
	/** index for status */
	public final static int I_STATUS = 6;
	/** index for analysis / attack result */
	public final static int I_RESULT = 7;
	/** index for arguments of analysis / attack result */
	public final static int I_RESULTARGS = 8;
	/** index for vulnerability severeness */
	public final static int I_SEVERENESS = 9;

	public final static Integer ST_RUN = new Integer( 0 );
	public final static Integer ST_SUS = new Integer( 1 );
	public final static Integer ST_STP = new Integer( 2 );
	public final static Integer ST_DON = new Integer( 3 );
	public final static Integer RS_SUCCESS = new Integer( 0 );
	public final static Integer RS_FAILURE = new Integer( 1 );
	/** selects all rows for a special action */
	public final static Integer ID_ALL = new Integer( -1 );

	private static final Class[] _t = { Integer.class, Integer.class, Integer.class, URL.class, 
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

	/**
	 * Creates a new AuditRow instance from a plain Object[].
	 * @param data the data this AuditRow is constructed with
	 */
	public AuditRow ( Object[] data ) {
		super( _t, _n, data );
	}
} // class AuditRow

