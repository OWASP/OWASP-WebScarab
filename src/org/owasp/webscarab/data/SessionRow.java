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

import java.net.URL;
import org.owasp.data.AbstractArrayRow;

/** 
 * Row description for an attack session row entry.
 * This represents a single target that is rendered vulnerable.
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public class SessionRow 
	extends AbstractArrayRow 
{
	/** index for suite id */ 
	public static final int I_SUITEID = 0;
	/** index for vulnerability signature */
	public static final int I_SIGNATURE = 1;
	/** index for vulnerable target URL */
	public static final int I_TARGET = 2;
	/** index for contents of vulnerable target URL */
	public static final int I_CONTENTS = 3;

	private static final Class[] _t = { Integer.class, Integer.class, URL.class, String.class };
	private static final String[] _n = {
		"suiteid",   // id for attack suite
		"signature", // id for the vulnerability signature
		"target" ,   // the URL (with port) that has been attacked successfully
		"contents",  // "body" part
	};
	
	/**
	 * Creates a new SessionRow instance from a plain Object[].
	 * @param data the data this AuditRow is constructed with
	 */
	public SessionRow ( Object[] data ) {
		super( _t, _n, data );
	}
} // class SessionRow

