package org.owasp.webscarab;

import java.io.File;
import java.io.FilenameFilter;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

public class Main {

	public static void main(String[] args) throws Exception {
		File dir = new File("./lib/");
		List urls = new ArrayList();
		findJars(dir, urls);
		ClassLoader loader = ClassLoader.getSystemClassLoader();
		if (urls.size() > 0) {
			URL[] u = (URL[]) urls.toArray(new URL[urls.size()]);
			loader = new URLClassLoader(u, loader);
		}
		Class c = loader.loadClass("org.owasp.webscarab.WebScarab");
		System.out.println(c);
		Method[] methods = c.getMethods();
		if (methods != null) {
			for (int i = 0; i< methods.length; i++) {
				System.out.println(methods[i]);
				if (methods[i].getName().equals("main")) {
					methods[i].invoke(null, new Object[] { args });
					return;
				}
			}
		}
	}
	
	private static void findJars(File dir, List urls) {
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
					urls.add(f.toURL());
				} catch (MalformedURLException mue) {
					mue.printStackTrace();
				}
			}
		}
	}
}
