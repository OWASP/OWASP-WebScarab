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
package org.owasp.webscarab.plugin.saml.swing;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.plugin.saml.SamlProxy;

/**
 *
 * @author Frank Cornelis
 */
public final class SamlReplayConversationAction extends AbstractAction {

    private final SamlProxy samlProxy;

    public SamlReplayConversationAction(SamlProxy samlProxy) {
        this.samlProxy = samlProxy;
        putValue(NAME, "Use for replay attack");
        putValue(SHORT_DESCRIPTION, "Use this SAML Response for replay attack");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = getValue("SAML-RESPONSE");
        if (o == null || !(o instanceof ConversationID)) {
            return;
        }
        ConversationID id = (ConversationID) o;
        this.samlProxy.setReplaySamlResponse(id);
    }

    @Override
    public void putValue(String key, Object value) {
        super.putValue(key, value);
        if (null == key) {
            return;
        }
        if (false == "SAML-RESPONSE".equals(key)) {
            return;
        }
        if (null == value) {
            setEnabled(false);
        } else {
            setEnabled(true);
        }
    }
}
