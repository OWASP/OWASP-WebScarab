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

import java.security.cert.X509Certificate;
import java.util.List;
import javax.swing.tree.TreePath;
import org.owasp.webscarab.util.swing.AbstractTreeModel;

/**
 *
 * @author Frank Cornelis
 */
public class CertPathTreeModel extends AbstractTreeModel {

    /**
     * List of X509 certificates.
     */
    private final List<X509Certificate> certificateChain;

    public CertPathTreeModel(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    @Override
    public Object getRoot() {
        return new TreeNode(this.certificateChain.size() - 1);
    }

    @Override
    public Object getChild(Object parent, int index) {
        TreeNode parentTreeNode = (TreeNode) parent;
        return parentTreeNode.getChild();
    }

    @Override
    public int getChildCount(Object parent) {
        TreeNode parentTreeNode = (TreeNode) parent;
        return parentTreeNode.getChildCount();
    }

    @Override
    public boolean isLeaf(Object node) {
        TreeNode treeNode = (TreeNode) node;
        return treeNode.isLeaf();
    }

    @Override
    public void valueForPathChanged(TreePath path, Object newValue) {
        // no editing
    }

    public class TreeNode {

        private final int certificateIdx;

        public TreeNode(int certificateIdx) {
            this.certificateIdx = certificateIdx;
        }

        public int getCertificateIdx() {
            return this.certificateIdx;
        }

        public boolean isLeaf() {
            if (this.certificateIdx == 0) {
                return true;
            }
            return false;
        }

        public int getChildCount() {
            if (isLeaf()) {
                return 0;
            }
            return 1;
        }

        public TreeNode getChild() {
            return new TreeNode(this.certificateIdx - 1);
        }

        public X509Certificate getCertificate() {
            return CertPathTreeModel.this.certificateChain.get(this.certificateIdx);
        }

        @Override
        public String toString() {
            X509Certificate certificate = getCertificate();
            return certificate.getSubjectX500Principal().toString();
        }
    }
}
