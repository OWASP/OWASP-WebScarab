/***********************************************************************
 *
 * $CVSHeader$
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
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */
package org.owasp.webscarab.plugin.wsfed;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.plugin.AbstractPluginModel;

/**
 *
 * @author Frank Cornelis
 */
public class WSFederationModel extends AbstractPluginModel {

    private final FrameworkModel model;
    private final ConversationModel wsfedConversationModel;

    public WSFederationModel(FrameworkModel model) {
        this.model = model;

        this.wsfedConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {

            public boolean shouldFilter(ConversationID id) {
                return !isWSFederationMessage(id);
            }
        };
    }

    private boolean isWSFederationMessage(ConversationID id) {
        if (null != this.model.getConversationProperty(id, "WTREALM")) {
            return true;
        }
        if (null != this.model.getConversationProperty(id, "WRESULT")) {
            return true;
        }
        return false;
    }

    public ConversationModel getConversationModel() {
        return this.wsfedConversationModel;
    }

    public void setSignInRequestMessage(ConversationID id, String wtrealm) {
        this.model.setConversationProperty(id, "WTREALM", wtrealm);
    }

    public void setSignInResponseMessage(ConversationID id, String wresult) {
        this.model.setConversationProperty(id, "WRESULT", wresult);
    }

    public String getReadableMessageType(ConversationID conversationId) {
        if (null != this.model.getConversationProperty(conversationId, "WTREALM")) {
            return "Sign-In Request";
        }
        if (null != this.model.getConversationProperty(conversationId, "WRESULT")) {
            return "Sign-In Response";
        }
        return "Unknown";
    }
}
