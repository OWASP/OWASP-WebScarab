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
public class AXFetchResponseAttribute {

    private String attributeType;
    private final String alias;
    private String value;
    private boolean signed;

    public AXFetchResponseAttribute(String alias) {
        this(null, alias, null, false);
    }
    
    public AXFetchResponseAttribute(String attributeType, String alias, String value, boolean signed) {
        this.attributeType = attributeType;
        this.alias = alias;
        this.value = value;
        this.signed = signed;
    }

    public String getAlias() {
        return this.alias;
    }

    public String getAttributeType() {
        return this.attributeType;
    }

    public boolean isSigned() {
        return this.signed;
    }

    public String getValue() {
        return this.value;
    }

    public void setAttributeType(String attributeType) {
        this.attributeType = attributeType;
    }

    public void setSigned(boolean signed) {
        this.signed = signed;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
