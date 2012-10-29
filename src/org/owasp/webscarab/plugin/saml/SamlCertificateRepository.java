/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 Frank Cornelis <info@frankcornelis.be>
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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.webscarab.httpclient.AbstractCertificateRepository;

/**
 *
 * @author Frank Cornelis
 */
public class SamlCertificateRepository extends AbstractCertificateRepository {

    public final static String SELECTED_KEY = "SELECTED KEY";
    public final static String SELECTED_KEY_ENTRY = "SELECTED KEY ENTRY";
    
    private PropertyChangeSupport propertyChangeSupport = new PropertyChangeSupport(this);
    
    @Override
    public void unlockKey(int keystoreIndex, int aliasIndex, String keyPassword) throws KeyStoreException, KeyManagementException {
        String fingerprint = getFingerPrint(getCertificate(keystoreIndex, aliasIndex));
        this.propertyChangeSupport.firePropertyChange(SELECTED_KEY, null, fingerprint);
        
        KeyStore keyStore = (KeyStore) this._keyStores.get(keystoreIndex);
        String alias = getAliasAt(keystoreIndex, aliasIndex);
        try {
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(alias, null);
            this.propertyChangeSupport.firePropertyChange(SELECTED_KEY_ENTRY, null, privateKeyEntry);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SamlCertificateRepository.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableEntryException ex) {
            Logger.getLogger(SamlCertificateRepository.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        this.propertyChangeSupport.addPropertyChangeListener(listener);
    }
    
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        this.propertyChangeSupport.removePropertyChangeListener(listener);
    }
}
