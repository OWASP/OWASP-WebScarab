package org.owasp.webscarab.ui.swing;

import java.io.File;

import javax.swing.JFrame;

public interface WebScarabUI extends Runnable {

	public JFrame getFrame();
	
	public void addPlugin(final SwingPluginUI plugin);
	
	public void loadSession(File session);

	public void createTemporarySession();
	
}
