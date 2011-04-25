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

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.event.EventListenerList;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.plugin.proxy.ProxyPlugin;

/**
 * WebScarab SAML Proxy plugin.
 * This plugin allows to modify the SAML Messages so simulate certain attacks.
 * 
 * @author Frank Cornelis
 */
public class SamlProxy extends ProxyPlugin implements SamlProxyConfig {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private boolean corruptSignature;
    private boolean removeSignature;
    private boolean replay;
    private ConversationID replayId;
    private boolean injectRemoteReference;
    private String remoteReference;
    private boolean injectAttribute;
    private String attributeName;
    private String attributeValue;
    private boolean injectSubject;
    private String subject;
    private boolean injectPublicDoctype;
    private String dtdUri;
    private boolean attack;
    private boolean injectRelayState;
    private String relayState;
    private boolean signSamlMessage;
    private KeyStore.PrivateKeyEntry privateKeyEntry;
    private EventListenerList _listenerList = new EventListenerList();
    private SamlModel samlModel;

    public String getPluginName() {
        return "SAML Proxy";
    }

    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new SamlHTTPClient(in, this);
    }

    public void setCorruptSignature(boolean corruptSignature) {
        this.corruptSignature = corruptSignature;
        updateAttackState();
    }

    public boolean doCorruptSignature() {
        return this.corruptSignature;
    }

    public void setRemoveSignature(boolean removeSignature) {
        this.removeSignature = removeSignature;
        updateAttackState();
    }

    public boolean doRemoveSignature() {
        return this.removeSignature;
    }

    public void setReplaySamlResponse(ConversationID id) {
        this.replayId = id;
        fireReplayChanged(id);
    }

    public void setReplay(boolean replay) {
        this.replay = replay;
        updateAttackState();
    }

    public boolean doReplay() {
        return this.replay;
    }

    public void addSamlProxyListener(SamlProxyListener listener) {
        _listenerList.add(SamlProxyListener.class, listener);
    }

    public void removeSamlProxyListener(SamlProxyListener listener) {
        _listenerList.remove(SamlProxyListener.class, listener);
    }

    private void fireReplayChanged(ConversationID replayId) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this even)
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == SamlProxyListener.class) {
                try {
                    ((SamlProxyListener) listeners[i + 1]).replayChanged(replayId);
                } catch (Exception e) {
                    _logger.log(Level.SEVERE, "Unhandled exception: {0}", e);
                }
            }
        }
    }

    public String getReplaySamlResponse() {
        return this.samlModel.getSAMLMessage(this.replayId);
    }

    public void init(SamlModel samlModel) {
        this.samlModel = samlModel;
    }

    public void setInjectRemoteReference(boolean injectRemoteReference) {
        this.injectRemoteReference = injectRemoteReference;
        updateAttackState();
    }

    public boolean doInjectRemoteReference() {
        return this.injectRemoteReference;
    }

    public void setRemoteReference(String remoteReference) {
        this.remoteReference = remoteReference;
    }

    public String getRemoteReference() {
        return this.remoteReference;
    }

    public void setInjectAttribute(boolean injectAttribute) {
        this.injectAttribute = injectAttribute;
        updateAttackState();
    }

    public void setInjectionAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public void setInjectionAttributeValue(String attributeValue) {
        this.attributeValue = attributeValue;
    }

    public boolean doInjectAttribute() {
        return this.injectAttribute;
    }

    public String getInjectionAttributeName() {
        return this.attributeName;
    }

    public String getInjectionAttributeValue() {
        return this.attributeValue;
    }

    public void setInjectSubject(boolean injectSubject) {
        this.injectSubject = injectSubject;
        updateAttackState();
    }

    public void setInjectionSubject(String injectionSubject) {
        this.subject = injectionSubject;
    }

    public boolean doInjectSubject() {
        return this.injectSubject;
    }

    public String getInjectionSubject() {
        return this.subject;
    }

    public boolean doSomething() {
        return this.attack;
    }

    private void updateAttackState() {
        this.attack = this.corruptSignature | this.injectAttribute | this.injectRemoteReference
                | this.injectSubject | this.removeSignature | this.replay | this.injectPublicDoctype |
                this.injectRelayState | this.signSamlMessage;
    }

    public void setInjectPublicDoctype(boolean injectPublicDoctype) {
        this.injectPublicDoctype = injectPublicDoctype;
        updateAttackState();
    }

    public void setDtdUri(String dtdUri) {
        this.dtdUri = dtdUri;
    }

    public boolean doInjectPublicDoctype() {
        return this.injectPublicDoctype;
    }

    public String getDtdUri() {
        return this.dtdUri;
    }

    public void setInjectRelayState(boolean injectRelayState) {
        this.injectRelayState = injectRelayState;
        updateAttackState();
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }

    public boolean doInjectRelayState() {
        return this.injectRelayState;
    }

    public String getRelayState() {
        return this.relayState;
    }

    public void setSignSamlMessage(boolean signSamlMessage) {
        this.signSamlMessage = signSamlMessage;
        updateAttackState();
    }

    public boolean doSignSamlMessage() {
        return this.signSamlMessage;
    }

    public PrivateKeyEntry getPrivateKeyEntry() {
        return this.privateKeyEntry;
    }
    
    public void setPrivateKeyEntry(PrivateKeyEntry privateKeyEntry) {
        this.privateKeyEntry = privateKeyEntry;
    }
}
