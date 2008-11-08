/*
 * TextComponentContextMenu.java
 *
 * Taken from code provided by Santhosh Kumar
 * See http://www.jroller.com/santhosh/entry/context_menu_for_textcomponents
 */

package org.owasp.webscarab.util.swing;

import java.awt.AWTEvent;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import javax.swing.AbstractAction;
import javax.swing.JPopupMenu;
import javax.swing.MenuSelectionManager;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;

/**
 *
 * @author rdawes
 */
public class TextComponentContextMenu extends EventQueue{
    
    protected void dispatchEvent(AWTEvent event){
        super.dispatchEvent(event);
        
        // interested only in mouseevents
        if(!(event instanceof MouseEvent))
            return;
        
        MouseEvent me = (MouseEvent)event;
        
        // interested only in popuptriggers
        if(!me.isPopupTrigger())
            return;
        
        // me.getComponent(...) retunrs the heavy weight component on which event occured
        Component comp = SwingUtilities.getDeepestComponentAt(me.getComponent(), me.getX(), me.getY());
        
        // interested only in textcomponents
        if(!(comp instanceof JTextComponent))
            return;
        
        // no popup shown by user code
        if(MenuSelectionManager.defaultManager().getSelectedPath().length>0)
            return;
        
        // create popup menu and show
        JTextComponent tc = (JTextComponent)comp;
        JPopupMenu menu = new JPopupMenu();
        menu.add(new CutAction(tc));
        menu.add(new CopyAction(tc));
        menu.add(new PasteAction(tc));
        menu.add(new DeleteAction(tc));
        menu.addSeparator();
        menu.add(new SelectAllAction(tc));
        
        Point pt = SwingUtilities.convertPoint(me.getComponent(), me.getPoint(), tc);
        menu.show(tc, pt.x, pt.y);
    }
    
    private static class CutAction extends AbstractAction {
        /**
		 * 
		 */
		private static final long serialVersionUID = 5259448700110788753L;
		JTextComponent comp;
        
        public CutAction(JTextComponent comp){
            super("Cut");
            this.comp = comp;
        }
        
        public void actionPerformed(ActionEvent e){
            comp.cut();
        }
        
        public boolean isEnabled(){
            return comp.isEditable()
            && comp.isEnabled()
            && comp.getSelectedText()!=null;
        }
    }
    
    private static class PasteAction extends AbstractAction{
        /**
		 * 
		 */
		private static final long serialVersionUID = 2284758389817935638L;
		JTextComponent comp;
        
        public PasteAction(JTextComponent comp){
            super("Paste");
            this.comp = comp;
        }
        
        public void actionPerformed(ActionEvent e){
            comp.paste();
        }
        
        public boolean isEnabled(){
            if (comp.isEditable() && comp.isEnabled()){
                Transferable contents = Toolkit.getDefaultToolkit().getSystemClipboard().getContents(this);
                return contents.isDataFlavorSupported(DataFlavor.stringFlavor);
            }else
                return false;
        }
    }
    
    private static class DeleteAction extends AbstractAction{
        /**
		 * 
		 */
		private static final long serialVersionUID = -2623797972969659203L;
		JTextComponent comp;
        
        public DeleteAction(JTextComponent comp){
            super("Delete");
            this.comp = comp;
        }
        
        public void actionPerformed(ActionEvent e){
            comp.replaceSelection(null);
        }
        
        public boolean isEnabled(){
            return comp.isEditable()
            && comp.isEnabled()
            && comp.getSelectedText()!=null;
        }
    }
    
    private static class CopyAction extends AbstractAction{
        /**
		 * 
		 */
		private static final long serialVersionUID = -7049993248136391935L;
		JTextComponent comp;
        
        public CopyAction(JTextComponent comp){
            super("Copy");
            this.comp = comp;
        }
        
        public void actionPerformed(ActionEvent e){
            comp.copy();
        }
        
        public boolean isEnabled(){
            return comp.isEnabled()
            && comp.getSelectedText()!=null;
        }
    }
    
    private static class SelectAllAction extends AbstractAction{
        /**
		 * 
		 */
		private static final long serialVersionUID = 792587916551631284L;
		JTextComponent comp;
        
        public SelectAllAction(JTextComponent comp){
            super("Select All");
            this.comp = comp;
        }
        
        public void actionPerformed(ActionEvent e){
            comp.selectAll();
        }
        
        public boolean isEnabled(){
            return comp.isEnabled()
            && comp.getText().length()>0;
        }
    }
}
