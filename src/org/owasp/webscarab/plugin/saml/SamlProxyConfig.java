/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2010 FedICT
 * Copyright (c) 2010 Frank Cornelis <info@frankcornelis.be>
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

package org.owasp.webscarab.plugin.saml;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.List;
import org.owasp.webscarab.model.NamedValue;

/**
 *
 * @author Frank Cornelis
 */
public interface SamlProxyConfig {

    boolean doCorruptSignature();

    boolean doRemoveSignature();

    boolean doReplay();

    String getReplaySamlResponse();

    boolean doInjectRemoteReference();

    String getRemoteReference();

    boolean doInjectAttribute();
    
    List<NamedValue> getInjectionAttributes();

    boolean doInjectSubject();
    
    Occurences getSubjectOccurences();

    String getInjectionSubject();

    boolean doSomething();

    boolean doInjectPublicDoctype();

    String getDtdUri();

    boolean doInjectRelayState();

    String getRelayState();

    boolean doSignSamlMessage();

    public PrivateKeyEntry getPrivateKeyEntry();
    
    boolean doSignWrapAttack();
    
    Wrapper getWrapper();
    
    SignatureType getWrapperTargetSignature();
    
    boolean doRenameTopId();
    
    boolean doRenameAssertionId();
    
    boolean doRenameLastAssertionId();
    
    boolean doRemoveAssertionSignature();
    
    Occurences getAttributeOccurences();
}
