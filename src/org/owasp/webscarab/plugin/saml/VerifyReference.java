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

import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.ReferenceNotInitializedException;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Element;

/**
 *
 * @author Frank Cornelis
 */
public class VerifyReference extends Reference {

    private static final Logger LOG = Logger.getLogger(VerifyReference.class.getName());

    public VerifyReference(Element element, Manifest manifest)
            throws XMLSecurityException {
        super(element, "", manifest);
    }

    public void init() throws Base64DecodingException, XMLSecurityException {
        generateDigestValue();
        LOG.log(Level.FINE, "original digest: {0}", Base64.encode(getDigestValue()));
    }

    public boolean hasChanged() {
        try {
            return false == verify();
        } catch (ReferenceNotInitializedException e) {
            return false;
        } catch (XMLSecurityException e) {
            return false;
        }
    }
}
