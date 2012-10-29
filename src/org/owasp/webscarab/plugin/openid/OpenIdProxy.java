/***********************************************************************
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 FedICT
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
 */
package org.owasp.webscarab.plugin.openid;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.plugin.proxy.ProxyPlugin;

/**
 *
 * @author Frank Cornelis
 */
public class OpenIdProxy extends ProxyPlugin implements OpenIdProxyConfig {

    private boolean corruptSignature;
    private boolean removeSignature;
    private boolean removeRequestedAttribute;
    private String removeAttributeType;
    private boolean appendAttribute;
    private String appendAttributeType;
    private String appendAttributeAlias;
    private String appendAttributeValue;
    private boolean removeReqAssocHandle;
    private boolean removeRespAssocHandle;
    
    private boolean attack;

    @Override
    public String getPluginName() {
        return "OpenID Proxy";
    }

    @Override
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new OpenIdHTTPClient(in, this);
    }

    @Override
    public boolean doSomething() {
        return this.attack;
    }

    private void updateAttackState() {
        this.attack = this.corruptSignature || this.removeSignature || this.removeRequestedAttribute || this.appendAttribute
                || this.removeReqAssocHandle || this.removeRespAssocHandle;
    }

    public void setCorruptSignature(boolean corruptSignature) {
        this.corruptSignature = corruptSignature;
        updateAttackState();
    }

    @Override
    public boolean doCorruptSignature() {
        return this.corruptSignature;
    }

    public void setRemoveSignature(boolean removeSignature) {
        this.removeSignature = removeSignature;
        updateAttackState();
    }

    @Override
    public boolean doRemoveSignature() {
        return this.removeSignature;
    }

    public void setRemoveRequestedAttribute(boolean removeRequestedAttribute) {
        this.removeRequestedAttribute = removeRequestedAttribute;
        updateAttackState();
    }

    public void setAppendAttribute(boolean appendAttribute) {
        this.appendAttribute = appendAttribute;
        updateAttackState();
    }

    public void setRemoveAttributeType(String removeAttributeType) {
        this.removeAttributeType = removeAttributeType;
    }

    public void setAppendAttributeType(String appendAttributeType) {
        this.appendAttributeType = appendAttributeType;
    }

    public void setAppendAttributeAlias(String appendAttributeAlias) {
        this.appendAttributeAlias = appendAttributeAlias;
    }

    public void setAppendAttributeValue(String appendAttributeValue) {
        this.appendAttributeValue = appendAttributeValue;
    }

    @Override
    public boolean doRemoveRequestedAttribute() {
        return this.removeRequestedAttribute;
    }

    @Override
    public boolean doAppendAttribute() {
        return this.appendAttribute;
    }

    @Override
    public String getRemoveAttributeType() {
        return this.removeAttributeType;
    }

    @Override
    public String getAppendAttributeType() {
        return this.appendAttributeType;
    }

    @Override
    public String getAppendAttributeAlias() {
        return this.appendAttributeAlias;
    }

    @Override
    public String getAppendAttributeValue() {
        return this.appendAttributeValue;
    }

    public void setRemoveRequestAssociationHandle(boolean removeReqAssocHandle) {
        this.removeReqAssocHandle = removeReqAssocHandle;
        updateAttackState();
    }

    public void setRemoveResponseAssociationHandle(boolean removeRespAssocHandle) {
        this.removeRespAssocHandle = removeRespAssocHandle;
        updateAttackState();
    }

    @Override
    public boolean doRemoveRequestAssociationHandle() {
        return this.removeReqAssocHandle;
    }

    @Override
    public boolean doRemoveResponseAssociationHandle() {
        return this.removeRespAssocHandle;
    }
}
