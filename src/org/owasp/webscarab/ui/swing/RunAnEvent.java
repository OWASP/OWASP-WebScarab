/*
 * RunAnEvent.java
 *
 * Created on 28 June 2002, 14:49
 */
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
package org.owasp.webscarab.ui.swing;
import java.net.URL;
import java.net.MalformedURLException;
import org.owasp.webscarab.ui.swing.util.Module;
import org.owasp.webscarab.ui.swing.util.AuditRowBean;
import javax.swing.SwingUtilities;



/**
 * puts the data onto the swing event thread
 * @author  thp
 * @version 
 */
public class RunAnEvent implements Runnable {

    private Module _targ; 
    private AuditRowBean _arb;
    
    public RunAnEvent(Module mod, AuditRowBean data){
	_targ = mod;
	_arb = data;
	SwingUtilities.invokeLater(this);
    }
    public void run () {
	_targ.setData(_arb);
    }
}
