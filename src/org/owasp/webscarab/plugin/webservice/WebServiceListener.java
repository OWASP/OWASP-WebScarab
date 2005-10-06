/*
 * WebServiceListener.java
 *
 * Created on 06 October 2005, 11:54
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.util.EventListener;

/**
 *
 * @author rdawes
 */
public interface WebServiceListener extends EventListener {
    
    void servicesChanged();
    
}
