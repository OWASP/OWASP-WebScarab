/**
 *
 */
package org.owasp.webscarab.ui.swing.editors;

import java.awt.GridBagLayout;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import javax.swing.JPanel;

import org.openamf.AMFBody;
import org.openamf.AMFHeader;
import org.openamf.AMFMessage;
import org.openamf.io.AMFDeserializer;

import flashgateway.io.ASObject;

import javax.swing.JTextPane;
import java.awt.GridBagConstraints;
import javax.swing.JTabbedPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import java.awt.BorderLayout;

/**
 * Panel for displaying parsed AMF requests/responses
 * @author Peter Gwiazda - p.gwiazda@done.pl
 *
 */
public class AMFPanel extends JPanel implements ByteArrayEditor {
    
    private static final long serialVersionUID = 1L;
    
    private byte[] bytesData = null;
    
    private JTextPane infoTextPane = null;
    
    private JTabbedPane amfTabbedPane = null;
    
    private JScrollPane infoScrollPane = null;
    
    private JPanel dataPane = null;
    
        /* (non-Javadoc)
         * @see org.owasp.webscarab.ui.swing.editors.ByteArrayEditor#getBytes()
         */
    public byte[] getBytes() {
        return bytesData;
    }
    
        /* (non-Javadoc)
         * @see org.owasp.webscarab.ui.swing.editors.ByteArrayEditor#isModified()
         */
    public boolean isModified() {
        return false;
    }
    
        /* (non-Javadoc)
         * @see org.owasp.webscarab.ui.swing.editors.ByteArrayEditor#setBytes(java.lang.String, byte[])
         */
    public void setBytes(String contentType, byte[] bytes) {
        //contentType is always application/x-amf
        this.bytesData = bytes;
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(this.bytesData));
        try {
            AMFDeserializer deserializer =  new AMFDeserializer(dis);
            AMFMessage message = deserializer.getAMFMessage();
            
            //Info panel
            StringBuffer sb = new StringBuffer();
            sb.append("Version: "+message.getVersion()+"\n");
            sb.append("Headers:" + message.getHeaderCount()+"\n");
            for (int i=0;i<message.getHeaderCount();i++){
                AMFHeader header = message.getHeader(i);
                sb.append(header.toString()+"\n\n");
            }
            sb.append("Bodies: "+message.getBodyCount()+"\n");
            
            for (int i=0;i<message.getBodyCount();i++){
                AMFBody messagebody = message.getBody(i);
                sb.append("Body : "+(i+1)+"\n");
                sb.append("   Service Name: "+messagebody.getServiceName()+"\n");
                sb.append("   Method Name: "+messagebody.getServiceMethodName()+"\n");
                sb.append("   Response: "+messagebody.getResponse()+"\n");
                sb.append("   Target: "+messagebody.getTarget()+"\n");
                sb.append("   Type: " + AMFBody.getObjectTypeDescription(messagebody.getType())+"\n");
                
            }
            this.getInfoTextPane().setText(sb.toString());
            
            //Data panel
            ObjectPanel oPanel = new ObjectPanel();
            if (message.getBodyCount() > 1) {
                HashMap bodies = new HashMap();
                for (int i=0;i<message.getBodyCount();i++){
                    bodies.put("Body :"+(i+1), message.getBody(i).getValue());
                    
                    oPanel.setObject(bodies);
                }
            } else {
                oPanel.setObject(message.getBody(0).getValue());
            }
            
            
            this.getDataPane().add(oPanel,BorderLayout.CENTER);
            
            //Recordsets
            //TODO:Recordsets are found as Custom Class...need to chceck it.
            for (int i=0;i<message.getBodyCount();i++){
                //recordset is an ASObject too which is a HashMap
                if (message.getBody(i).getValue() instanceof flashgateway.io.ASObject) {
                    ASObject object = (ASObject) message.getBody(i).getValue();
                    //check if it's a RecordSet
                    if (object.containsKey("serverinfo") && object.get("serverinfo") instanceof ASObject) {
                        ASObject rs = (ASObject)object.get("serverinfo");
                        
                        if (rs.containsKey("cursor")
                        && rs.containsKey("initialdata")
                        && rs.containsKey("id")
                        && rs.containsKey("servicename")
                        && rs.containsKey("totalcount")
                        && rs.containsKey("version")
                        && rs.containsKey("columnnames")
                        ) {
                            
                            //Looks like a recordset
                            this.addRecordsetPanel(rs,i+1);
                        }
                    }
                }
                
            }
            
            
            
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        
    }
    
    private void addRecordsetPanel(ASObject rs, int number) {
        TableModel model = new RecordsetTableModel(rs);
        JTable rsTable = new JTable(model);
        JScrollPane  rsScroll = new JScrollPane(rsTable);
        getAmfTabbedPane().addTab("Recordset "+number, rsScroll);
        
        
        
    }
    
        /* (non-Javadoc)
         * @see org.owasp.webscarab.ui.swing.editors.ByteArrayEditor#setEditable(boolean)
         */
    public void setEditable(boolean editable) {
        //This panel is to render. We can't edit data here.
    }
    
    /**
     * This is the default constructor
     */
    public AMFPanel() {
        super();
        setName("AMF");
        initialize();
    }
    public String[] getContentTypes() {
        return new String[] { "application/x-amf" };
    }
    /**
     * This method initializes this
     *
     * @return void
     */
    private void initialize() {
        GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
        gridBagConstraints1.fill = GridBagConstraints.BOTH;
        gridBagConstraints1.weighty = 1.0;
        gridBagConstraints1.weightx = 1.0;
        this.setSize(300, 200);
        this.setLayout(new GridBagLayout());
        this.add(getAmfTabbedPane(), gridBagConstraints1);
    }
    
    /**
     * This method initializes infoTextPane
     *
     * @return javax.swing.JTextPane
     */
    private JTextPane getInfoTextPane() {
        if (infoTextPane == null) {
            infoTextPane = new JTextPane();
        }
        return infoTextPane;
    }
    
    /**
     * This method initializes amfTabbedPane
     *
     * @return javax.swing.JTabbedPane
     */
    private JTabbedPane getAmfTabbedPane() {
        if (amfTabbedPane == null) {
            amfTabbedPane = new JTabbedPane();
            amfTabbedPane.addTab("Info", null, getInfoScrollPane(), null);
            amfTabbedPane.addTab("Data", null, getDataPane(), null);
        }
        return amfTabbedPane;
    }
    
    /**
     * This method initializes infoScrollPane
     *
     * @return javax.swing.JScrollPane
     */
    private JScrollPane getInfoScrollPane() {
        if (infoScrollPane == null) {
            infoScrollPane = new JScrollPane();
            infoScrollPane.setViewportView(getInfoTextPane());
        }
        return infoScrollPane;
    }
    
    /**
     * This method initializes dataPane
     *
     * @return javax.swing.JPanel
     */
    private JPanel getDataPane() {
        if (dataPane == null) {
            dataPane = new JPanel();
            dataPane.setLayout(new BorderLayout());
        }
        return dataPane;
    }
    
    private class RecordsetTableModel extends AbstractTableModel {
        private ArrayList data=null;
        private ArrayList colNames=null;
        
        public RecordsetTableModel(ASObject rs) {
            if (rs.get("columnnames") instanceof ArrayList) {
                if (rs.get("initialdata") instanceof ArrayList ) {
                    ArrayList rows = (ArrayList)rs.get("initialdata");
                    
                    boolean allOk=true;
                    Iterator it = rows.iterator();
                    while (it.hasNext()) {
                        Object row = it.next();
                        if (row instanceof ArrayList) {
                            Vector vRow = new Vector((ArrayList)row);
                            
                        } else {
                            allOk =false;
                            break;
                        }
                    }
                    if (allOk) {
                        this.data = rows;
                        this.colNames = (ArrayList) rs.get("columnnames");
                    }
                }
            }
            
        }
        
        public int getColumnCount() {
            if (this.colNames == null) {
                return 0;
            } else {
                return this.colNames.size();
            }
        }
        
        public String getColumnName(int no) {
            if (colNames == null) {
                return null;
            } else {
                return this.colNames.get(no).toString();
            }
        }
        
        public int getRowCount() {
            if (data == null) {
                return 0;
            } else {
                return data.size();
            }
        }
        
        public Object getValueAt(int rowNo, int colNo) {
            ArrayList row = (ArrayList) data.get(rowNo);
            return row.get(colNo);
        }
        
    }
    
}


