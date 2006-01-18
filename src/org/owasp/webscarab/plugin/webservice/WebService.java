/*
 * WebService.java
 *
 * Created on 06 October 2005, 08:31
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.wsdl.Binding;
import javax.wsdl.BindingInput;
import javax.wsdl.BindingOperation;
import javax.wsdl.BindingOutput;
import javax.wsdl.Definition;
import javax.wsdl.Input;
import javax.wsdl.Message;
import javax.wsdl.Operation;
import javax.wsdl.Part;
import javax.wsdl.Port;
import javax.wsdl.Service;
import javax.wsdl.WSDLException;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.soap.SOAPAddress;
import javax.wsdl.extensions.soap.SOAPBinding;
import javax.wsdl.extensions.soap.SOAPBody;
import javax.wsdl.extensions.soap.SOAPOperation;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.owasp.webscarab.httpclient.HTTPClientFactory;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 *
 * @author rdawes
 */
public class WebService implements Plugin {
    
    /** The default SOAP encoding to use. */
    public final static String DEFAULT_SOAP_ENCODING_STYLE = "http://schemas.xmlsoap.org/soap/encoding/";
    
    // XML namespace constants
    public final static String SOAP_NS =
            "http://schemas.xmlsoap.org/soap/envelope/";
    public final static String XSD_NS =
            "http://www.w3.org/2001/XMLSchema";
    public final static String XSI_NS =
            "http://www.w3.org/2001/XMLSchema-instance";
    
    private Framework _framework;
    private WebServiceModel _model;
    
    private Request _request = null;
    private Response _response = null;
    private Date _responseDate = null;
    
    private Logger _logger = Logger.getLogger(getClass().toString());
    
    /** Creates a new instance of WebService */
    public WebService(Framework framework) {
        _framework = framework;
        _model = new WebServiceModel(framework.getModel());
    }
    
    public WebServiceModel getModel() {
        return _model;
    }
    
    public Definition getWSDL(String location) throws MalformedURLException, IOException, SAXException, WSDLException {
        if (location.startsWith("http://") || location.startsWith("https://")) {
            Request request = new Request();
            request.setMethod("GET");
            request.setVersion("HTTP/1.0");
            request.setURL(new HttpUrl(location));
            Response response = HTTPClientFactory.getInstance().fetchResponse(request);
            byte[] wsdl = response.getContent();
            Definition definition = parseWSDL(location, parseXML(wsdl));
            if (definition != null) {
                _framework.addConversation(request, response, getPluginName());
            }
            return definition;
        } else {
            File file = new File(location);
            FileInputStream fis = new FileInputStream(file);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buff = new byte[2048];
            int got;
            while ((got=fis.read(buff))>0) {
                baos.write(buff,0,got);
            }
            Definition definition = parseWSDL(file.toURI().toString(), parseXML(baos.toByteArray()));
            return definition;
        }
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        String ctype = response.getHeader("Content-Type");
        if (ctype != null && ctype.startsWith("text/xml")) {
            byte[] content = response.getContent();
            if (content == null || content.length == 0)
                return;
            try {
                Document doc = parseXML(content);
                parseWSDL(request.getURL().toString(), doc);
                _model.setWSDLResponse(id);
            } catch (Exception ignored) {
            }
        }
    }
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "WebServices";
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return null;
    }
    
    public String getStatus() {
        return "Idle";
    }
    
    public boolean isBusy() {
        return false;
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public void run() {
        _model.setRunning(true);
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
    }
    
    public boolean stop() {
        _model.setRunning(false);
        return true;
    }
    
    public Definition getDefinition(ConversationID id) throws WSDLException, SAXException {
        String url = _model.getURL(id).toString();
        byte[] wsdl = _model.getWSDL(id);
        if (wsdl != null) {
            Document doc = parseXML(wsdl);
            return parseWSDL(url, doc);
        }
        return null;
    }
    
    public void selectWSDL(Definition definition) throws WSDLException {
        _model.setDefinition(definition);
        Schema schema = createSchemaFromTypes(_model.getDefinition());
        if (schema != null) {
            // must do this before setServices, since setServices triggers
            // the UI to read the schema
            _model.setSchema(schema);
            ServiceInfo[] services = buildComponents(_model.getDefinition());
            _model.setServices(services);
        } else {
            _logger.warning("Can't proceed with an empty schema!");
            _model.setDefinition(null);
            _model.setSchema(null);
            _model.setServices(null);
        }
    }
    
    /**
     * Builds and adds parameters to the supplied info object
     * given a SOAP Message definition (from WSDL)
     *
     * @param   operationInfo   The component to build message text for
     * @param   msg    The SOAP Message definition that has parts to defined parameters for
     */
    public Value[] buildValues(OperationInfo operationInfo, Message msg) {
        List values = new ArrayList();
        
        // Get the message parts
        List msgParts = msg.getOrderedParts(null);
        
        // Process each part
        Iterator iter = msgParts.iterator();
        
        while(iter.hasNext()) {
            // Get each part
            Part part = (Part)iter.next();
            
            // Add content for each message part
            String partName = part.getName();
            
            if(partName != null) {
                Value value = constructValue(partName, part.getTypeName());
                values.add(value);
            }
        }
        
        return (Value[]) values.toArray(new Value[0]);
    }
    
    public Value constructValue(String name, QName typeName) {
        Type type = _model.getSchema().getType(typeName);
        if (type == null) {
            return new SimpleValue(name, typeName, null);
        } else if (type.isComplex()) {
            ComplexValue value = new ComplexValue(name, typeName, type);
            Field[] fields = type.getFields();
            for (int i=0; i<fields.length; i++) {
                value.setValue(fields[i].getName(), constructValue(fields[i].getName(), fields[i].getType()));
            }
            return value;
        } else if (type.isArray()) {
            return new ArrayValue(name, typeName, type, type.getComponentQName(), _model.getSchema().getType(type.getComponentQName()));
        } else {
            return new SimpleValue(name, typeName, type);
        }
    }
    
    public Response invokeOperation(OperationInfo operation, Value[] values) throws MalformedURLException, IOException {
        Request request = new Request();
        request.setMethod("POST");
        HttpUrl targetUrl = new HttpUrl(operation.getTargetURL());
        request.setURL(targetUrl);
        request.setVersion("HTTP/1.0");
        request.addHeader("Accept","application/soap+xml, application/dime, multipart/related, text/*");
        request.addHeader("Host", targetUrl.getHost() + ":" + targetUrl.getPort());
        request.addHeader("Content-Type", "text/xml; charset=utf-8");
        request.addHeader("SOAPAction", "\""+operation.getSoapActionURI()+"\"");
        NamedValue[] headers = _model.getExtraHeaders();
        if (headers != null && headers.length > 0) {
            for (int i=0; i< headers.length; i++) {
                if (headers[i] != null)
                    request.addHeader(headers[i]);
            }
        }
        Document doc = constructMessageDocument(operation, values);
        StringWriter sw = new StringWriter();
        new DOMWriter().write(sw, doc);
        String body = sw.toString();
        request.addHeader("Content-Length", String.valueOf(body.length()));
        request.setContent(body.getBytes());
        Response response = HTTPClientFactory.getInstance().fetchResponse(request);
        if (response != null) {
            _framework.addConversation(request, response, getPluginName());
        }
        return response;
    }
    
    private Document constructMessageDocument(OperationInfo operation, Value[] values) {
        try {
            Message message = operation.getInputMessage();
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document document = dbf.newDocumentBuilder().newDocument();
            Element env = createElement(document, "Envelope", SOAP_NS);
            String xsdPrefix = _model.getSchema().getPrefix(XSD_NS);
            env.setAttribute("xmlns:"+xsdPrefix, XSD_NS);
            String xsiPrefix = _model.getSchema().getPrefix(XSI_NS);
            env.setAttribute("xmlns:"+xsiPrefix, XSI_NS);
            Element bodyElem = createElement(env, "Body", SOAP_NS);
            String action = operation.getTargetMethodName();
            String nsURI = operation.getTargetObjectURI();
            Element actionElem = createElement(bodyElem, action, nsURI);
            
            String encodingStyle = operation.getEncodingStyle();
            if (!encodingStyle.equals("literal")) {
                Attr enc = createAttr(bodyElem, "encodingStyle", SOAP_NS);
                enc.setValue(encodingStyle);
            }
            
            // Get the message parts
            List msgParts = message.getOrderedParts(null);
            
            // Process each part
            Iterator iter = msgParts.iterator();
            
            int i=0;
            while(iter.hasNext()) {
                // Get each part
                Part part = (Part)iter.next();
                Element element = createElement(actionElem, part.getName());
                setElementValue(operation.getStyle(), operation.getEncodingStyle(), element, values[i++]);
            }
//            fixNamespaces(document);
            return document;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    private Element createElement(Node parent, String variableName, String namespaceURI) {
        Document doc;
        if (parent instanceof Document) {
            doc = (Document) parent;
        } else {
            doc = parent.getOwnerDocument();
        }
        if (namespaceURI != null) {
            String prefix = _model.getSchema().getPrefix(namespaceURI);
            if (prefix == null)
                throw new RuntimeException("No prefix found for " + namespaceURI);
            Element element = doc.createElementNS(namespaceURI, prefix + ":" + variableName);
            parent.appendChild(element);
            return element;
        } else {
            Element element = doc.createElement(variableName);
            parent.appendChild(element);
            return element;
        }
    }
    
    private Element createElement(Node parent, String variableName) {
        Document doc;
        if (parent instanceof Document) {
            doc = (Document) parent;
        } else {
            doc = parent.getOwnerDocument();
        }
        Element element = doc.createElement(variableName);
        parent.appendChild(element);
        return element;
    }
    
    private Attr createAttr(Element element, String attrName, String namespaceURI) {
        String prefix = _model.getSchema().getPrefix(namespaceURI);
        if (prefix == null)
            throw new RuntimeException("No prefix found for " + namespaceURI);
        Document doc;
        if (element instanceof Document) {
            doc = (Document) element;
        } else {
            doc = element.getOwnerDocument();
        }
        Attr attr = doc.createAttributeNS(namespaceURI, prefix + ":" + attrName);
        element.setAttributeNodeNS(attr);
        return attr;
    }
    
    private void setElementValue(String style, String encodingStyle, Element element, Value value) {
        Document doc = element.getOwnerDocument();
        if (style.equalsIgnoreCase("rpc")) {
            Attr typeAttr = doc.createAttributeNS(XSI_NS, "xsi:type");
            QName typeQName;
            if (value instanceof ArrayValue) {
                typeQName = ((ArrayValue)value).getComponentTypeName();
            } else {
                typeQName = value.getTypeName();
            }
            String prefix = _model.getSchema().getPrefix(typeQName.getNamespaceURI());
            typeAttr.setValue(prefix + ":" + typeQName.getLocalPart());
            element.setAttributeNodeNS(typeAttr);
        }
        if (value instanceof SimpleValue) {
            SimpleValue sv = (SimpleValue) value;
            if (sv.getValue() == null) {
                if (style.equalsIgnoreCase("rpc")) {
                    Attr nilAttr = doc.createAttributeNS(XSI_NS, "xsi:nil");
                    nilAttr.setValue("true");
                    element.setAttributeNodeNS(nilAttr);
                }
            } else {
                setElementValue(element, sv.getValue());
            }
        } else if (value instanceof ComplexValue) {
            ComplexValue cv = (ComplexValue) value;
            for (int i=0; i<cv.getFieldCount(); i++) {
                String name = cv.getFieldName(i);
                Element child = createElement(element, name);
                setElementValue(style, encodingStyle, child, cv.getValue(name));
            }
        } else if (value instanceof ArrayValue) {
            if (style.equalsIgnoreCase("rpc")) {
                Attr nilAttr = doc.createAttributeNS(XSI_NS, "xsi:nil");
                nilAttr.setValue("true");
                element.setAttributeNodeNS(nilAttr);
            }
        }
    }
    
    private void setElementValue(Element element, Object value) {
        NodeList children = element.getChildNodes();
        Node text;
        if (children.getLength() > 1) {
            throw new RuntimeException("Can't set the value for a node with multiple children");
        } else if (children.getLength() == 1) {
            text = children.item(0);
            if (text.getNodeType() != Node.TEXT_NODE) {
                throw new RuntimeException("Child is not a text node : " + text);
            }
        } else {
            text = element.getOwnerDocument().createTextNode("");
//            element.setAttributeNS(XSI_NS, "xsi:type", "xsd:string");
            element.appendChild(text);
        }
        String s = value == null ? "" : value.toString();
        text.setNodeValue(s);
    }
    
    private Document parseXML(byte[] xml) throws SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(false);
        factory.setNamespaceAware(true);
        try {
            InputSource src = new InputSource(new ByteArrayInputStream(xml));
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new XMLErrorHandler());
            Document document = builder.parse(src);
            return document;
        } catch (ParserConfigurationException pce) {
            // Parser with specified options can't be built
            pce.printStackTrace();
        } catch (IOException impossible) {
        }
        return null;
    }
    
    private Definition parseWSDL(String url, Document wsdl) throws WSDLException {
        WSDLFactory wsdlFactory = WSDLFactory.newInstance();
        WSDLReader wsdlReader = wsdlFactory.newWSDLReader();
        return wsdlReader.readWSDL(url, wsdl);
    }
    
    /**
     * Builds a List of ServiceInfo components for each Service defined in a WSDL Document
     *
     * @param wsdlURI A URI that points to a WSDL XML Definition. Can be a filename or URL.
     *
     * @return A List of SoapComponent objects populated for each service defined
     *         in a WSDL document. A null is returned if the document can't be read.
     */
    private ServiceInfo[] buildComponents(Definition def) {
        // The list of components that will be returned
        List serviceList = new ArrayList();
        
        // Get the services defined in the document
        Map services = def.getServices();
        
        if(services != null) {
            // Create a component for each service defined
            Iterator svcIter = services.values().iterator();
            
            for(int i = 0; svcIter.hasNext(); i++) {
                // Create a new ServiceInfo component for each service found
                ServiceInfo serviceInfo = new ServiceInfo();
                
                // Populate the new component from the WSDL Definition read
                populateComponent(serviceInfo, (Service)svcIter.next());
                
                // Add the new component to the List to be returned
                serviceList.add(serviceInfo);
            }
        }
        
        // return the List of services we created
        return (ServiceInfo[]) serviceList.toArray(new ServiceInfo[0]);
    }
    
    /**
     * Creates a schema based on the types defined by a WSDL document
     *
     * @param   wsdlDefinition    The WSDL4J instance of a WSDL definition.
     *
     * @return  A schema is returned if the WSDL definition contains
     *          a types element. null is returned otherwise.
     */
    protected Schema createSchemaFromTypes(Definition wsdlDefinition) {
        // Get the schema element from the WSDL definition
        Element[] schemaElements = null;
        
        if(wsdlDefinition.getTypes() != null) {
            ExtensibilityElement[] schemaExtElems = findExtensibilityElements(wsdlDefinition.getTypes().getExtensibilityElements(), "schema");
            
            if(schemaExtElems != null && schemaExtElems.length > 0) {
                schemaElements = new Element[schemaExtElems.length];
                for (int i=0; i<schemaExtElems.length; i++) {
                    if (schemaExtElems[i] instanceof javax.wsdl.extensions.schema.Schema) {
                        schemaElements[i] = ((javax.wsdl.extensions.schema.Schema)schemaExtElems[i]).getElement();
                    } else {
                        schemaElements[i] = null;
                        System.err.println("Looked for schema elements, but got " + schemaExtElems[i].getClass());
                    }
                }
            }
        }
        
        // Add namespaces from the WSDL
        Map namespaces = wsdlDefinition.getNamespaces();
        
        if(schemaElements == null || schemaElements.length == 0) {
            // No schema to read
            System.err.println("Unable to find schema extensibility element in WSDL, using an empty schema!");
            return new Schema(namespaces, new Element[0]);
        }
        
        try {
            return new Schema(namespaces, schemaElements);
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Populates a ServiceInfo instance from the specified Service definiition
     *
     * @param   component      The component to populate
     * @param   service        The Service to populate from
     *
     * @return The populated component is returned representing the Service parameter
     */
    private ServiceInfo populateComponent(ServiceInfo component, Service service) {
        // Get the qualified service name information
        QName qName = service.getQName();
        
        // Get the service's namespace URI
        String namespace = qName.getNamespaceURI();
        
        // Use the local part of the qualified name for the component's name
        String name = qName.getLocalPart();
        
        // Set the name
        component.setName(name);
        
        // Get the defined ports for this service
        Map ports = service.getPorts();
        
        // Use the Ports to create OperationInfos for all request/response messages defined
        Iterator portIter = ports.values().iterator();
        
        while(portIter.hasNext()) {
            // Get the next defined port
            Port port = (Port)portIter.next();
            
            // Get the Port's Binding
            Binding binding = port.getBinding();
            
            // Now we will create operations from the Binding information
            List operations = buildOperations(binding);
            
            // Process objects built from the binding information
            Iterator operIter = operations.iterator();
            
            while(operIter.hasNext()) {
                OperationInfo operation = (OperationInfo)operIter.next();
                
                // Set the namespace URI for the operation.
                operation.setNamespaceURI(namespace);
                
                // Find the SOAP target URL
                ExtensibilityElement addrElem = findExtensibilityElement(port.getExtensibilityElements(), "address");
                
                if(addrElem != null && addrElem instanceof SOAPAddress) {
                    // Set the SOAP target URL
                    SOAPAddress soapAddr = (SOAPAddress)addrElem;
                    operation.setTargetURL(soapAddr.getLocationURI());
                }
                
                // Add the operation info to the component
                component.addOperation(operation);
            }
        }
        
        return component;
    }
    
    /**
     * Creates Info objects for each Binding Operation defined in a Port Binding
     *
     * @param binding The Binding that defines Binding Operations used to build info objects from
     *
     * @return A List of built and populated OperationInfos is returned for each Binding Operation
     */
    private List buildOperations(Binding binding) {
        // Create the array of info objects to be returned
        List operationInfos = new ArrayList();
        
        // Get the list of Binding Operations from the passed binding
        List operations = binding.getBindingOperations();
        
        if(operations != null && !operations.isEmpty()) {
            // Determine encoding
            ExtensibilityElement soapBindingElem = findExtensibilityElement(binding.getExtensibilityElements(), "binding");
            String style = "document"; // default
            
            if(soapBindingElem != null && soapBindingElem instanceof SOAPBinding) {
                SOAPBinding soapBinding = (SOAPBinding)soapBindingElem;
                style = soapBinding.getStyle();
            }
            
            // For each binding operation, create a new OperationInfo
            Iterator opIter = operations.iterator();
            int i = 0;
            
            while(opIter.hasNext()) {
                BindingOperation oper = (BindingOperation)opIter.next();
                
                // We currently only support soap:operation bindings
                // filter out http:operations for now until we can dispatch them properly
                ExtensibilityElement operElem = findExtensibilityElement(oper.getExtensibilityElements(), "operation");
                
                if(operElem != null && operElem instanceof SOAPOperation) {
                    // Create a new operation info
                    OperationInfo operationInfo = new OperationInfo(style);
                    
                    // Populate it from the Binding Operation
                    buildOperation(operationInfo, oper);
                    
                    // Add to the return list
                    operationInfos.add(operationInfo);
                }
            }
        }
        
        return operationInfos;
    }
    
    /**
     * Populates an OperationInfo from the specified Binding Operation
     *
     * @param   operationInfo      The component to populate
     * @param   bindingOper        A Binding Operation to define the OperationInfo from
     *
     * @return The populated OperationInfo object is returned.
     */
    private OperationInfo buildOperation(OperationInfo operationInfo, BindingOperation bindingOper) {
        // Get the operation
        Operation oper = bindingOper.getOperation();
        
        // Set the name using the operation name
        operationInfo.setTargetMethodName(oper.getName());
        
        // Set the action URI
        ExtensibilityElement operElem = findExtensibilityElement(bindingOper.getExtensibilityElements(), "operation");
        
        if(operElem != null && operElem instanceof SOAPOperation) {
            SOAPOperation soapOperation = (SOAPOperation)operElem;
            operationInfo.setSoapActionURI(soapOperation.getSoapActionURI());
        }
        
        // Get the Binding Input
        BindingInput bindingInput = bindingOper.getBindingInput();
        
        // Get the Binding Output
        BindingOutput bindingOutput = bindingOper.getBindingOutput();
        
        // Get the SOAP Body
        ExtensibilityElement bodyElem = findExtensibilityElement(bindingInput.getExtensibilityElements(), "body");
        
        if(bodyElem != null && bodyElem instanceof SOAPBody) {
            SOAPBody soapBody = (SOAPBody)bodyElem;
            
            // The SOAP Body contains the encoding styles
            List styles = soapBody.getEncodingStyles();
            String encodingStyle = null;
            
            if(styles != null) {
                // Use the first in the list
                encodingStyle = styles.get(0).toString();
            }
            
            if(encodingStyle == null) {
                // An encoding style was not found, give it a default
                encodingStyle = DEFAULT_SOAP_ENCODING_STYLE;
            }
            
            // Assign the encoding style value
            operationInfo.setEncodingStyle(encodingStyle.toString());
            
            // The SOAP Body contains the target object's namespace URI.
            operationInfo.setTargetObjectURI(soapBody.getNamespaceURI());
        }
        
        // Get the Operation's Input definition
        Input inDef = oper.getInput();
        
        if(inDef != null) {
            // Build input parameters
            Message inMsg = inDef.getMessage();
            
            if(inMsg != null) {
                // Set the name of the operation's input message
                operationInfo.setInputMessageName(inMsg.getQName().getLocalPart());
                operationInfo.setInputMessage(inMsg);
            }
        }
        
        // Finished, return the populated object
        return operationInfo;
    }
    
    /**
     * Returns the desired ExtensibilityElement if found in the List
     *
     * @param   extensibilityElements   The list of extensibility elements to search
     * @param   elementType             The element type to find
     *
     * @return  Returns the first matching element of type found in the list
     */
    private static ExtensibilityElement findExtensibilityElement(List extensibilityElements, String elementType) {
        if(extensibilityElements != null) {
            Iterator iter = extensibilityElements.iterator();
            
            while(iter.hasNext()) {
                ExtensibilityElement element = (ExtensibilityElement)iter.next();
                
                if(element.getElementType().getLocalPart().equalsIgnoreCase(elementType)) {
                    // Found it
                    return element;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Returns the desired ExtensibilityElement if found in the List
     *
     * @param   extensibilityElements   The list of extensibility elements to search
     * @param   elementType             The element type to find
     *
     * @return  Returns the first matching element of type found in the list
     */
    private static ExtensibilityElement[] findExtensibilityElements(List extensibilityElements, String elementType) {
        List results = new ArrayList();
        if(extensibilityElements != null) {
            Iterator iter = extensibilityElements.iterator();
            
            while(iter.hasNext()) {
                ExtensibilityElement element = (ExtensibilityElement)iter.next();
                
                if(element.getElementType().getLocalPart().equalsIgnoreCase(elementType)) {
                    results.add(element);
                }
            }
        }
        return (ExtensibilityElement[]) results.toArray(new ExtensibilityElement[0]);
    }
    
    private class XMLErrorHandler implements org.xml.sax.ErrorHandler {
        // ignore fatal errors (an exception is guaranteed)
        public void fatalError(SAXParseException exception)
        throws SAXException {
        }
        
        // treat validation errors as fatal
        public void error(SAXParseException e)
        throws SAXParseException {
            throw e;
        }
        
        // dump warnings too
        public void warning(SAXParseException err)
        throws SAXParseException {
            System.out.println("** Warning"
                    + ", line " + err.getLineNumber()
                    + ", uri " + err.getSystemId());
            System.out.println("   " + err.getMessage());
        }
    }
    
}
