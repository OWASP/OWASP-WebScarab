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
    private boolean attack;
    
    public String getPluginName() {
        return "OpenID Proxy";
    }

    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new OpenIdHTTPClient(in, this);
    }

    public boolean doSomething() {
        return this.attack;
    }
    
    private void updateAttackState() {
        this.attack = this.corruptSignature;
    }

    public void setCorruptSignature(boolean corruptSignature) {
        this.corruptSignature = corruptSignature;
        updateAttackState();
    }

    public boolean doCorruptSignature() {
        return this.corruptSignature;
    }
}
