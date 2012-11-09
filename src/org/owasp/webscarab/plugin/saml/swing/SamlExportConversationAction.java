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
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Logger;
import javax.swing.AbstractAction;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.plugin.saml.SamlModel;

/**
 *
 * @author Frank Cornelis
 */
public class SamlExportConversationAction extends AbstractAction {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final SamlModel samlModel;

    public SamlExportConversationAction(SamlModel samlModel) {
        this.samlModel = samlModel;
        putValue(NAME, "Export SAML Message to file");
        putValue(SHORT_DESCRIPTION, "Exports the embedded SAML Message to a file");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = getValue("CONVERSATION");
        if (o == null || !(o instanceof ConversationID)) {
            return;
        }
        ConversationID id = (ConversationID) o;
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export SAML message from conversation " + id);

        int result = fileChooser.showDialog(null, "Export");
        if (JFileChooser.APPROVE_OPTION != result) {
            return;
        }
        File file = fileChooser.getSelectedFile();

        if (file.exists()) {
            int overwriteResult =  JOptionPane.showConfirmDialog(null, "Overwrite file \"" + file.getAbsolutePath() + "\"?",
                    "Existing file", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (JOptionPane.CANCEL_OPTION == overwriteResult) {
                return;
            }
        }

        String samlMessage = this.samlModel.getDecodedSAMLMessage(id);
        try {
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(samlMessage);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException ioe) {
            _logger.warning("Error writing SAML message to file '" + file.getAbsolutePath() + "' : " + ioe);
        }
    }
}
