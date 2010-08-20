package org.owasp.webscarab.ui.swing.editors;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

import org.owasp.webscarab.util.swing.JTreeTable;
import org.owasp.webscarab.util.swing.treetable.DefaultTreeTableModel;

import flex.messaging.io.SerializationContext;
import flex.messaging.io.amf.ActionContext;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.amf.AmfMessageDeserializer;
import flex.messaging.io.amf.AmfMessageSerializer;
import flex.messaging.io.amf.AmfTrace;

/**
 * Panel for parsing and manipulating AMF0 and AMF3 requests/responses. It is
 * currently only possible to change String and long values.
 * 
 * Currently this panels relies on code from Adobe's BlazeDS project.
 * 
 * NB: This class was ported from Java 1.5 and from some of SwingLabs' swingx
 * components and may therefore need more testing.
 * 
 * @author Martin Clausen <mclausen@deloitte.dk>
 * 
 */
public class AMFPanel extends JPanel implements ByteArrayEditor, ActionListener {
	/** The parsed ActionMessage object. */
	private ActionMessage message;

	private ActionContext messageContext;

	private SerializationContext serialContext;

	/** The AMF encoded message. */
	private byte[] messageBytes;

	/** The views are organized in tabs. */
	private JTabbedPane tabs;

	private JTreeTable treeTable;

	private JTextPane stringsArea;

	private JTextPane hexArea;

	private JButton exportButton;

	private JFileChooser fc;

	public static boolean DEBUG = true;

	/** Default constructor. */
	public AMFPanel() {
		super(new GridLayout(1, 1));
		setName("AMF");

		// Organize the views in tabs
		tabs = new JTabbedPane();

		// The following line enables to use scrolling tabs.
		tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
	}

	// ByteArrayEditor METHODS

	public String[] getContentTypes() {
		return new String[] { "application/x-amf" };
	}

	public boolean isModified() {
		return true;
	}

	public void setEditable(boolean editable) {
		// Ignore
	}

	public void setBytes(String contentType, byte[] messageBytes) {
		this.messageBytes = (byte[]) messageBytes.clone();
		parseAMFMessage();
		addTreeTable();
		updateStringsArea();
		updateHexArea();
		add(tabs);
	}

	public byte[] getBytes() {
		encodeAMFMessage();
		return (byte[]) messageBytes.clone();
	}

	private void parseAMFMessage() {
		try {
			serialContext = SerializationContext.getSerializationContext();
			serialContext.instantiateTypes = false;

			AmfTrace trace = null;
			if (DEBUG)
				trace = new AmfTrace();

			AmfMessageDeserializer amfder = new AmfMessageDeserializer();
			amfder.initialize(serialContext, new ByteArrayInputStream(
					messageBytes), trace);

			message = new ActionMessage();
			messageContext = new ActionContext();
			amfder.readMessage(message, messageContext);

			if (DEBUG)
				System.err.println(trace);
		} catch (Exception x) {
			x.printStackTrace();
		}
	}

	private void encodeAMFMessage() {
		try {
			AmfTrace trace = null;
			if (DEBUG)
				trace = new AmfTrace();

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			AmfMessageSerializer amfser = new AmfMessageSerializer();
			amfser.initialize(serialContext, baos, trace);
			amfser.writeMessage(message);
			messageBytes = baos.toByteArray();

			if (DEBUG) {
				System.out.println(dump("", messageBytes, 0,
						messageBytes.length));
				System.err.println(trace);
			}
		} catch (Exception x) {
			x.printStackTrace();
		}
	}

	private static byte[] encodeAMFMessage(ActionMessage message) {
		byte[] messageBytes = null;
		try {
			AmfTrace trace = null;
			if (DEBUG)
				trace = new AmfTrace();

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			AmfMessageSerializer amfser = new AmfMessageSerializer();
			SerializationContext context = SerializationContext
					.getSerializationContext();
			context.instantiateTypes = false;
			amfser.initialize(context, baos, trace);
			amfser.writeMessage(message);
			messageBytes = baos.toByteArray();

			if (DEBUG) {
				System.out.println(dump("", messageBytes, 0,
						messageBytes.length));
				System.err.println(trace);
			}
		} catch (Exception x) {
			x.printStackTrace();
		}
		return messageBytes;
	}

	// /////////////////////////////////////////////////////////////////////////////////////
	// ///////// ///////////
	// ///////// GUI SETUP ///////////
	// ///////// ///////////
	// /////////////////////////////////////////////////////////////////////////////////////

	private void addTreeTable() {
		AMFTreeTableModel dataTreeTableModel = generateModel();
		treeTable = new JTreeTable(dataTreeTableModel);

		tabs.addTab("AMF", new JScrollPane(treeTable));
		tabs.setMnemonicAt(0, KeyEvent.VK_1);
	}

	private String strings(byte[] data) {
		StringBuffer sb = new StringBuffer();
		boolean foundString = false;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i = 0; i < data.length; i++) {
			int ch = (char) (data[i] & 0xff);
			if (ch >= ' ' && ch < 0x7f) {
				baos.write(ch);
				foundString = true;
			} else if (foundString) {
				byte[] tmp = baos.toByteArray();
				sb.append(new String(tmp)).append('\n');
				baos.reset();
				foundString = false;
			}
		}
		return sb.toString();
	}

	void updateStringsArea() {
		if (stringsArea == null) {
			stringsArea = new JTextPane();
			stringsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
			stringsArea.setEditable(false);
			stringsArea.setText(strings(messageBytes));
			tabs.addTab("Strings", new JScrollPane(stringsArea));
			tabs.setMnemonicAt(1, KeyEvent.VK_2);
		} else {
			stringsArea.setText(strings(messageBytes));
		}
	}

	void updateHexArea() {
		if (hexArea == null) {
			fc = new JFileChooser();

			exportButton = new JButton("Export");
			exportButton.addActionListener(this);

			JPanel buttonPanel = new JPanel();
			buttonPanel.add(exportButton);

			hexArea = new JTextPane();
			hexArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
			hexArea.setEditable(false);
			hexArea.setText(dump("", messageBytes, 0, messageBytes.length));

			JPanel hexPanel = new JPanel(new BorderLayout());
			hexPanel.add(buttonPanel, BorderLayout.PAGE_END);
			hexPanel.add(new JScrollPane(hexArea), BorderLayout.CENTER);

			tabs.addTab("HEX", hexPanel);
			tabs.setMnemonicAt(2, KeyEvent.VK_3);
		} else {
			hexArea.setText(dump("", messageBytes, 0, messageBytes.length));
		}
	}

	public void actionPerformed(ActionEvent e) {
		try {
			if (e.getSource() == exportButton) {
				int returnVal = fc.showSaveDialog(this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					if (DEBUG)
						System.out.print("Exporting data to file "
								+ file.getCanonicalPath() + "...");
					FileOutputStream fos = new FileOutputStream(file);
					fos.write(messageBytes);
					fos.close();
					if (DEBUG)
						System.out.println("done");
				}
			}
		} catch (Exception x) {
			x.printStackTrace();
		}
	}

	// /////////////////////////////////////////////////////////////////////////////////////
	// ///////// ///////////
	// ///////// DATA MODEL ///////////
	// ///////// ///////////
	// /////////////////////////////////////////////////////////////////////////////////////

	private static class AMFData {
		private String field;

		private String type;

		private Class typeClass;

		private String value;

		private Object object;

		private boolean isEditable;

		private ActionMessage message;

		private static String OBJ_TYPE(Object o) {
			if (o == null)
				return "Null";
			String s = o.getClass().getName();
			StringTokenizer token = new StringTokenizer(s, ".");
			while (token.hasMoreElements())
				s = (String) token.nextElement();
			return s;
		}

		private static String OBJ_VALUE(Object o) {
			if (o == null)
				return "";
			return o.toString();
		}

		private static Class OBJ_CLASS(Object o) {
			if (o == null)
				return null;
			return o.getClass();
		}

		public AMFData(String field, String type, String value) {
			this.field = field;
			this.type = type;
			this.typeClass = null;
			this.value = value;
			this.object = null;
			this.isEditable = false;
		}

		public AMFData(String field, Object object, boolean isEditable,
				ActionMessage message) {
			try {
				this.field = field;

				// Call appropriate get method
				Object value;
				if (object instanceof HashMap) {
					value = ((HashMap) object).get(field);
				} else {
					Method m = object.getClass().getMethod("get" + field, (Class[]) null);
					value = m.invoke(object, (Object[]) null);
				}

				this.type = OBJ_TYPE(value);
				this.typeClass = OBJ_CLASS(value);
				this.value = OBJ_VALUE(value);
				this.object = object;
				this.isEditable = isEditable;
				this.message = message;
			} catch (Exception x) {
				x.printStackTrace();
			}
		}

		public String getField() {
			return field;
		}

		public String getType() {
			return type;
		}

		public String getValue() {
			return value;
		}

		public void setValue(String value) {
			if (!isEditable)
				return;
			if (DEBUG)
				System.out.println("Setting " + value);
			try {
				// Invoke appropriate set method
				if (object instanceof HashMap) {
					((HashMap) object).put(field, value);
				} else {
					Method m;
					// XXX arhhggg, pls fix me...
					if (type.equals("Long")) {
						m = object.getClass().getMethod("set" + field,
								new Class[] { long.class });
						m.invoke(object, new Object[] { new Long(value) });

					} else {
						m = object.getClass().getMethod("set" + field,
								new Class[] { typeClass });
						m.invoke(object, new Object[] { value });
					}
				}

				// Update instance, this is needed for updating GUI
				this.value = value;

				encodeAMFMessage(message);
			} catch (Exception x) {
				x.printStackTrace();
			}
		}

		public String toString() {
			return field;
		}
	}

	private static class AMFTreeTableNode extends DefaultMutableTreeNode {
		public AMFTreeTableNode(AMFData data) {
			super(data);
		}

		public boolean isEditable(int column) {
			return (column == 2) ? true : false;
		}

		/**
		 * Called when done editing a cell from {@link DefaultTreeTableModel}.
		 */
		public void setValueAt(Object value, int column) {
			if (DEBUG) {
				System.out.println("Setting value at column " + column + " to "
						+ value + " (an instance of " + value.getClass() + ")");
			}

			if (getUserObject() instanceof AMFData) {
				AMFData data = (AMFData) getUserObject();
				switch (column) {
				case 2:
					data.setValue(value.toString());
				}
			}
		}

		/**
		 * must override this for setValue from {@link DefaultTreeTableModel} to
		 * work properly!
		 */
		public int getColumnCount() {
			return 3;
		}

		/**
		 * Called when done editing a cell from {@link DefaultTreeTableModel}.
		 */
		public Object getValueAt(int column) {
			if (getUserObject() instanceof AMFData) {
				AMFData data = (AMFData) getUserObject();
				switch (column) {
				case 0:
					return data.getField();
				case 1:
					return data.getType();
				case 2:
					return data.getValue();
				}
			}
			throw new RuntimeException("Unknown user object: "
					+ getUserObject());
		}
	}

	private static class AMFTreeTableModel extends DefaultTreeTableModel {
		private static String[] columnNames = { "Field", "Type", "Value" };

		public AMFTreeTableModel(TreeNode node) {
			super(node);
		}

		public int getColumnCount() {
			return 3;
		}

		public String getColumnName(int column) {
			return columnNames[column];
		}

		public Class getColumnClass(int column) {
			// TODO Auto-generated method stub
			return super.getColumnClass(column);
		}

		public Object getValueAt(Object node, int column) {
			AMFTreeTableNode n = (AMFTreeTableNode) node;
			return n.getValueAt(column);
		}

		public boolean isCellEditable(Object node, int column) {
			if (column == 0)
				return true;
			AMFTreeTableNode n = (AMFTreeTableNode) node;
			return n.isEditable(column);
		}

		public void setValueAt(Object value, Object node, int column) {
			AMFTreeTableNode n = (AMFTreeTableNode) node;
			n.setValueAt(value, column);
		}
	}

	public AMFTreeTableModel generateModel() {
		DefaultMutableTreeNode rootNode = new AMFTreeTableNode(new AMFData(
				"Message", "", ""));

		AMFTreeTableNode headersNode = new AMFTreeTableNode(new AMFData(
				"Headers", "", ""));
		rootNode.add(headersNode);

		for (int i = 0; i < message.getHeaderCount(); i++) {
			if (DEBUG)
				System.out.println("Reading header: " + i);

			AMFTreeTableNode headerNode = new AMFTreeTableNode(new AMFData("["
					+ i + "]", "Header Part", ""));
			headersNode.add(headerNode);

			addObject(headerNode, message.getHeader(i));
		}

		AMFTreeTableNode bodiesNode = new AMFTreeTableNode(new AMFData(
				"Bodies", "", ""));
		rootNode.add(bodiesNode);

		for (int i = 0; i < message.getBodyCount(); i++) {
			if (DEBUG)
				System.out.println("Reading body: " + i);

			AMFTreeTableNode bodyNode = new AMFTreeTableNode(new AMFData("["
					+ i + "]", "Body Part", ""));
			bodiesNode.add(bodyNode);

			addObject(bodyNode, message.getBody(i));
		}

		return new AMFTreeTableModel(rootNode);
	}

	private boolean isComplex(Object object) {
		return (object instanceof Object[])
				|| (object instanceof HashMap)
				|| (object instanceof List)
				|| (object != null && object.getClass().getPackage().toString()
						.indexOf("flex.messaging.messages") > -1);
	}

	private void addObject(AMFTreeTableNode node, Object object) {
		try {
			if (object instanceof Object[]) {
				AMFTreeTableNode objectsNode = new AMFTreeTableNode(
						new AMFData("", "Array", ""));
				node.add(objectsNode);

				Object[] array = (Object[]) object;
				for (int i = 0; i < array.length; i++)
					addObject(objectsNode, array[i]);
			} else if (object instanceof HashMap) {
				AMFTreeTableNode hashNode = new AMFTreeTableNode(new AMFData(
						"", "HashMap", ""));
				node.add(hashNode);

				HashMap map = (HashMap) object;
				for (Iterator it = map.keySet().iterator(); it.hasNext();) {
					String key = (String) it.next();

					AMFTreeTableNode dataNode = new AMFTreeTableNode(
							new AMFData(key, map, true, message));
					hashNode.add(dataNode);
				}
				// } else if (object instanceof List) {
				// AMFTreeTableNode listNode =
				// new AMFTreeTableNode(new AMFData("", "List", ""));
				// node.add(listNode);
				//
				// List<?> list = (List<?>)object;
				// for (Iterator<?> it = list.iterator(); it.hasNext(); ) {
				// Object listobj = it.next();
				// if (isComplex(listobj))
				// addObject(listNode, listobj);
				// else {
				// String val = (String)it.next();
				//						
				// AMFTreeTableNode dataNode =
				// new AMFTreeTableNode(new AMFData("", val, ""));
				// listNode.add(dataNode);
				// }
				// }
			} else {
				Method[] methods = object.getClass().getMethods();
				for (int i = 0; i < methods.length; i++) {
					Method m = methods[i];
					String name = m.getName();
					Class[] paramTypes = m.getParameterTypes();
					if (name.startsWith("get") && !name.equals("getClass")
							&& paramTypes.length == 0) {
						Object val = m.invoke(object, (Object[]) null);
						if (isComplex(val))
							addObject(node, val);
						else {
							String getter = name.substring(3);
							AMFData data = new AMFData(getter, object, true,
									message);
							AMFTreeTableNode objectNode = new AMFTreeTableNode(
									data);
							node.add(objectNode);
						}
					}
				}
			}
		} catch (Exception x) {
			x.printStackTrace();
		}
	}

	private static final String NL = System.getProperty("line.separator", "\n");

	private static boolean isprint(int c) {
		return ((c >= 0 && c <= 33) || (c > 126 && c <= 256)) ? false : true;
	}

	static String dump(String desc, byte[] data, int off, int len) {
		final String hex = "0123456789abcdef";
		StringBuffer sb = new StringBuffer();
		if (desc.length() != 0)
			sb.append(desc + NL);
		int n = len / 16, i, o;
		for (i = 0; i < n; i++) {
			o = i * 16;
			sb.append(hex.charAt((o >>> 12) & 0x0f)); // offset
			sb.append(hex.charAt((o >>> 8) & 0x0f)); // offset
			sb.append(hex.charAt((o >>> 4) & 0x0f)); // offset
			sb.append(hex.charAt((o) & 0x0f)); // offset
			sb.append(": ");

			for (int j = 0; j < 16; j++) {
				o = data[off + i * 16 + j] & 0xff;
				sb.append(hex.charAt((o >>> 4) & 0x0f));
				sb.append(hex.charAt((o) & 0x0f));
				sb.append(" ");
			}

			sb.append("  ");
			for (int j = 0; j < 16; j++) {
				char c = (char) (data[off + i * 16 + j] & 0xff);
				sb.append(isprint(c) ? c : '.');
			}
			sb.append(NL);
		}
		if ((n = len % 16) != 0) {
			o = i * 16;
			sb.append(hex.charAt((o >>> 12) & 0x0f)); // offset
			sb.append(hex.charAt((o >>> 8) & 0x0f)); // offset
			sb.append(hex.charAt((o >>> 4) & 0x0f)); // offset
			sb.append(hex.charAt((o) & 0x0f)); // offset
			sb.append(": ");

			for (int j = 0; j < n; j++) {
				o = data[off + i * 16 + j] & 0xff;
				sb.append(hex.charAt((o >>> 4) & 0x0f));
				sb.append(hex.charAt((o) & 0x0f));
				sb.append(" ");
			}
			for (int j = n; j < 16; j++)
				sb.append("   ");

			sb.append("  ");
			for (int j = 0; j < n; j++) {
				char c = (char) (data[off + i * 16 + j] & 0xff);
				sb.append(isprint(c) ? c : '.');
			}
			sb.append(NL);
		}
		return sb.toString();
	}

	private static byte[] readfile(String filename) {
		byte[] tmp = null;
		try {
			RandomAccessFile raf = new RandomAccessFile(filename, "r");
			tmp = new byte[(int) raf.length()];
			raf.readFully(tmp);
			raf.close();
		} catch (Exception x) {
			x.printStackTrace();
		}
		return tmp;
	}

	public static void main(String[] args) {
		try {
			byte[] messageBytes = readfile("c:\\temp\\temp\\amf-passwd-res.bin");
			JFrame mainFrame = new JFrame("AMF Panel");
			mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
			AMFPanel amfPanel = new AMFPanel();
			amfPanel.setBytes("", messageBytes);
			mainFrame.getContentPane().add(amfPanel);
			Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
			mainFrame.setSize(screenSize.width * 2 / 3,
					screenSize.height * 2 / 3);
			mainFrame.setLocationRelativeTo(null);
			mainFrame.pack();
			mainFrame.setVisible(true);
		} catch (Exception x) {
			x.printStackTrace();
		}
	}
}
