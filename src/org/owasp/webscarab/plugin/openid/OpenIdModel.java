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

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.plugin.AbstractPluginModel;
import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author Frank Cornelis
 */
public class OpenIdModel extends AbstractPluginModel {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final FrameworkModel model;
    private final ConversationModel openIdConversationModel;

    public OpenIdModel(FrameworkModel model) {
        this.model = model;
        this.openIdConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {

            public boolean shouldFilter(ConversationID id) {
                return !isOpenIDMessage(id);
            }
        };
    }

    public void setOpenIDMessage(ConversationID id, String namespace) {
        this.model.setConversationProperty(id, "OPENID", namespace);
    }

    public boolean isOpenIDMessage(ConversationID id) {
        return this.model.getConversationProperty(id, "OPENID") != null;
    }

    public ConversationModel getOpenIDConversationModel() {
        return this.openIdConversationModel;
    }

    public void setOpenIDMessageType(ConversationID id, String messageType) {
        this.model.setConversationProperty(id, "OPENID_MODE", messageType);
    }

    public String getReadableOpenIDMessageType(ConversationID id) {
        String openIdMode = this.model.getConversationProperty(id, "OPENID_MODE");
        if (null == openIdMode) {
            return "Unknown";
        }
        if ("checkid_setup".equals(openIdMode)) {
            return "Request";
        }
        if ("id_res".equals(openIdMode)) {
            return "Response";
        }
        return "Unknown";
    }

    public List getParameters(ConversationID id) {
        List parameters = new LinkedList();
        Request request = this.model.getRequest(id);
        HttpUrl url = request.getURL();
        String query = url.getQuery();
        if (null != query) {
            NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid.")) {
                    NamedValue parameter = new NamedValue(name, value);
                    parameters.add(parameter);
                }
            }
        }
        return parameters;
    }

    public List getAXFetchRequestAttributes(ConversationID id) {
        List attributes = new LinkedList();
        Request request = this.model.getRequest(id);
        HttpUrl url = request.getURL();
        String query = url.getQuery();
        if (null != query) {
            NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
            // first locate the AX extension
            String alias = null;
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid.ns.")) {
                    if ("http://openid.net/srv/ax/1.0".equals(value)) {
                        alias = name.substring("openid.ns.".length());
                        break;
                    }
                }
            }
            if (null == alias) {
                return attributes;
            }
            _logger.info("AX alias: " + alias);
            // check the AX mode
            boolean isFetchRequest = false;
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".mode")) {
                    if ("fetch_request".equals(value)) {
                        isFetchRequest = true;
                        break;
                    }
                }
            }
            if (false == isFetchRequest) {
                return attributes;
            }
            // required aliases
            Set requiredAliases = new HashSet();
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".required")) {
                    String[] aliases = value.split(",");
                    requiredAliases.addAll(Arrays.asList(aliases));
                    break;
                }
            }
            // optional aliases
            Set optionalAliases = new HashSet();
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".if_available")) {
                    String[] aliases = value.split(",");
                    optionalAliases.addAll(Arrays.asList(aliases));
                    break;
                }
            }
            // get the fetch request attributes
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid." + alias + ".type.")) {
                    String attributeAlias = name.substring(("openid." + alias + ".type.").length());
                    boolean requiredAttribute = requiredAliases.contains(attributeAlias);
                    boolean optionalAttribute = optionalAliases.contains(attributeAlias);
                    AXFetchRequestAttribute attribute = new AXFetchRequestAttribute(value, attributeAlias, requiredAttribute, optionalAttribute);
                    attributes.add(attribute);
                }
            }
        }
        return attributes;
    }
}
