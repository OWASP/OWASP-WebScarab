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

import java.util.Date;
import java.util.logging.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

/**
 *
 * @author Frank Cornelis
 */
public class PAPEResponse {

    private final Logger _logger = Logger.getLogger(getClass().getName());
    private Date authenticationTime;
    private boolean phishingResistant;
    private boolean multiFactor;
    private boolean multiFactorPhysical;
    private boolean signed;

    public Date getAuthenticationTime() {
        return this.authenticationTime;
    }

    public void setAuthenticationTime(String authenticationTimeStr) {
        DateTimeFormatter dateTimeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH:mm:ss'Z'");
        DateTime dateTime = dateTimeFormatter.parseDateTime(authenticationTimeStr);
        this.authenticationTime = dateTime.withZoneRetainFields(DateTimeZone.UTC).toDate();
    }

    void setPhishingResistant(boolean phishingResistant) {
        this.phishingResistant = phishingResistant;
    }

    public boolean isPhishingResistant() {
        return this.phishingResistant;
    }

    void setMultiFactor(boolean multiFactor) {
        this.multiFactor = multiFactor;
    }

    public boolean isMultiFactor() {
        return this.multiFactor;
    }

    void setMultiFactorPhysical(boolean multiFactorPhysical) {
        this.multiFactorPhysical = multiFactorPhysical;
    }

    public boolean isMultiFactorPhysical() {
        return this.multiFactorPhysical;
    }
    
    void setSigned(boolean signed) {
        this.signed = signed;
    }
    
    public boolean isSigned() {
        return this.signed;
    }
}
