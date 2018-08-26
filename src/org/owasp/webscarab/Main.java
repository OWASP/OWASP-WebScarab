package org.owasp.webscarab;

import java.io.File;
import java.io.FilenameFilter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

public class Main {

	public static void main(String[] args) throws Exception {
		File dir = new File("./plugins/");
		List<URL> urls = new ArrayList<URL>();
		findJars(dir, urls);
		ClassLoader loader = ClassLoader.getSystemClassLoader();
		if (urls.size() > 0) {
			URL[] u = urls.toArray(new URL[urls.size()]);
			System.out.println("Creating new ClassLoader");
			Thread.currentThread().setContextClassLoader(new URLClassLoader(u, loader));
		} else {
			System.err.println("No plugins found!");
		}
		WebScarab.main(args);
	}
	
	private static void findJars(File dir, List<URL> urls) {
		if (!dir.isDirectory())
			return;
		FilenameFilter filter = new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.endsWith(".jar") || new File(dir, name).isDirectory();
			}
		};
		String[] items = dir.list(filter);
		if (items == null)
			return;
		for (int i=0; i<items.length; i++) {
			File f = new File(dir, items[i]);
			if (f.isDirectory()) {
				findJars(f, urls);
			} else {
				try {
					URL u = f.toURI().toURL();
					System.err.println("Adding " + u);
					urls.add(u);
				} catch (MalformedURLException mue) {
					mue.printStackTrace();
				}
			}
		}
	}
	
}
