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
package org.owasp.webscarab.plugin.openid.swing;

import javax.swing.DefaultComboBoxModel;
import org.openid4java.association.AssociationSessionType;

/**
 *
 * @author Frank Cornelis
 */
public class AssociationSessionComboBoxModel extends DefaultComboBoxModel {

    public AssociationSessionComboBoxModel() {
        super(new Object[]{new Item(AssociationSessionType.NO_ENCRYPTION_SHA1MAC),
                    new Item(AssociationSessionType.NO_ENCRYPTION_SHA256MAC),
                    new Item(AssociationSessionType.DH_SHA1),
                    new Item(AssociationSessionType.DH_SHA256)});
    }

    public AssociationSessionType getSelectedAssociationSessionType() {
        Item item = (Item) this.getSelectedItem();
        AssociationSessionType associationSessionType = item.getAssociationSessionType();
        return associationSessionType;
    }
    
    private static final class Item {

        private final AssociationSessionType associationSessionType;

        private Item(AssociationSessionType associationSessionType) {
            this.associationSessionType = associationSessionType;
        }
        
        public AssociationSessionType getAssociationSessionType() {
            return this.associationSessionType;
        }

        @Override
        public String toString() {
            return this.associationSessionType.getAssociationType() + " " + this.associationSessionType.getSessionType();
        }
    }
}
