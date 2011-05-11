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

/**
 *
 * @author Frank Cornelis
 */
public class AXFetchRequestAttribute {

    private final String attributeType;
    private final String alias;
    private final boolean required;
    private final boolean optional;

    public AXFetchRequestAttribute(String attributeType, String alias, boolean required, boolean optional) {
        this.attributeType = attributeType;
        this.alias = alias;
        this.required = required;
        this.optional = optional;
    }

    public String getAttributeType() {
        return this.attributeType;
    }

    public String getAlias() {
        return this.alias;
    }

    public boolean isRequired() {
        return this.required;
    }

    public boolean isOptional() {
        return this.optional;
    }
}
