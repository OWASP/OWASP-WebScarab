/**
 * *********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security Project
 * utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2010-2012 FedICT Copyright (c) 2010 Frank Cornelis
 * <info@frankcornelis.be>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at Sourceforge.net, a repository
 * for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */
package org.owasp.webscarab.plugin.saml.swing;

import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.util.logging.Logger;
import javax.swing.AbstractAction;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.plugin.saml.SamlModel;

/**
 *
 * @author Frank Cornelis
 */
public class OpenBrowserAction extends AbstractAction {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final SamlModel samlModel;

    public OpenBrowserAction(SamlModel samlModel) {
        this.samlModel = samlModel;
        putValue(NAME, "Open SAML Message in web browser");
        putValue(SHORT_DESCRIPTION, "Displays the SAML message within a web browser");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = getValue("CONVERSATION");
        if (o == null || !(o instanceof ConversationID)) {
            return;
        }
        ConversationID id = (ConversationID) o;

        if (false == Desktop.isDesktopSupported()) {
            _logger.warning("desktop not supported");
            return;
        }
        Desktop desktop = Desktop.getDesktop();
        if (false == desktop.isSupported(Desktop.Action.BROWSE)) {
            _logger.warning("desktop browse not supported");
            return;
        }

        File tmpFile;
        String samlMessage = this.samlModel.getDecodedSAMLMessage(id);
        try {
            tmpFile = File.createTempFile("saml-", ".xml");
            tmpFile.deleteOnExit();
            FileWriter fileWriter = new FileWriter(tmpFile);
            fileWriter.write(samlMessage);
            fileWriter.flush();
            fileWriter.close();
            desktop.browse(tmpFile.toURI());
        } catch (IOException ioe) {
            _logger.warning("Error writing SAML message to file: " + ioe);
        }
    }
}
