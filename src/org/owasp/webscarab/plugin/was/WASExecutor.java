/*
 * WASExecutor.java
 *
 * Created on October 11, 2003, 5:11 PM
 */

package org.owasp.webscarab.plugin.was;

import java.io.FileInputStream;
import java.io.IOException;

import org.owasp.vulnxml.factory.VulnFactory;
import org.owasp.vulnxml.model.vuln.WebApplicationTest;
import org.owasp.vulnxml.model.vuln.Variable;
import org.owasp.vulnxml.model.vuln.Item;
import org.owasp.vulnxml.model.vuln.Connection;
import org.owasp.vulnxml.model.vuln.Step;
import org.owasp.vulnxml.model.vuln.Request;
import org.owasp.vulnxml.model.vuln.MessageHeader;
import org.owasp.vulnxml.model.vuln.Header;
import org.owasp.vulnxml.model.vuln.Name;
import org.owasp.vulnxml.model.vuln.Value;
import org.owasp.vulnxml.model.vuln.Method;
import org.owasp.vulnxml.model.vuln.URI;
import org.owasp.vulnxml.model.vuln.Version;
import org.owasp.vulnxml.model.vuln.Response;
import org.owasp.vulnxml.model.vuln.SetVariable;
import org.owasp.vulnxml.model.vuln.Source;
import org.owasp.vulnxml.model.vuln.TestCriteria;
import org.owasp.vulnxml.model.vuln.Compare;

import org.owasp.util.Envelope;
import org.owasp.util.xml.Node;
import org.owasp.util.URLUtil;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import java.net.URL;
import java.net.MalformedURLException;

import org.owasp.webscarab.httpclient.URLFetcher;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 *
 * @author  rdawes
 */
public class WASExecutor {
    
    private Node _test;
    private URL _url;
    private Map _base;
    private String[] _variableNames = new String[0];
    private String[][] _variableValues = new String[1][0];
    
    /** Creates a new instance of WASExecutor */
    public WASExecutor(Node test, URL url) {
        _test = test;
        _url = url;
        Object[] o = _test.get( WebApplicationTest.MMB_VARIABLE);
        Node[] vars = new Node[o.length];
        for (int i=0; i<o.length; i++) { 
            vars[i] = (Node) o[i]; 
        }
        if (vars == null) {
            return;
        } else {
            calculateCrossProduct(vars);
        }
        for (int i=0; i<_variableValues.length; i++) {
            for (int j=0; j<_variableNames.length; j++) {
                System.out.println("Variation " + i + ": " + _variableNames[j] + " = '" + _variableValues[i][j] + "'");
            }
        }
        _base = new TreeMap();
        _base.put("scheme", url.getProtocol());
        _base.put("host", url.getHost());
        _base.put("port", Integer.toString(url.getPort() > 0 ? url.getPort() : url.getDefaultPort()));
        _base.put("path", URLUtil.pathWithoutFile(url));
        _base.put("file", URLUtil.pathFile(url));
    }
    
    public int getVariations() {
        return _variableValues.length;
    }
    
    private void calculateCrossProduct(Object[] variables) {
        int variations = 1;
        ArrayList vars = new ArrayList();
        _variableNames = new String[variables.length];
        for (int i=0; i<variables.length; i++) {
            if (variables[i] instanceof Node) {
                Node node = (Node) variables[i];
                _variableNames[i] = (String) node.get( Variable.MMB_NAME, 0);
                String type = (String) node.get( Variable.MMB_TYPE, 0);
                if (!type.equalsIgnoreCase("string")) {
                    System.out.println("Don't know how to handle variables of type " + type);
                }
                String[] items = getItems(node);
                variations = variations * items.length;
                vars.add(items);
            }
        }
        
        _variableValues = new String[variations][variables.length];
        int[] pos = new int[variables.length];
        for (int i=0; i<pos.length; i++) {
            pos[i] = 0;
        }
        int variation = 0;
        while (variation < variations) {
            for (int i=0; i<_variableNames.length; i++) {
                String[] items = (String[]) vars.get(i);
                _variableValues[variation][i] = items[pos[i]];
            }
            for (int i=_variableNames.length-1; i>=0; i--) {
                String[] items = (String[]) vars.get(i);
                pos[i]++;
                if (pos[i] == items.length) {
                    pos[i] = 0;
                } else {
                    break;
                }
            }
            variation++;
        }
    }
    
    private String[] getItems(Node variable) {
        Object[] item = variable.get( Variable.MMB_ITEM );
        if (item != null) {
            String[] items = new String[item.length];
            for (int j=0; j<item.length; j++) {
                Node node = (Node) item[j];
                items[j] = (String) node.get( Item.MMB_PCDATA, 0 );
                if (items[j] == null) {
                    items[j] = "";
                }
            }
            return items;
        }
        return new String[0];
    }
    
    public TestResult[] execute() throws IOException {
        TestResult[] results = new TestResult[getVariations()];
        for (int variation=0; variation<getVariations(); variation++) {
            results[variation] = execute(variation);
        }
        return results;
    }
    
    public TestResult execute(int variation) throws IOException {
        TreeMap variables = new TreeMap(_base);
        for (int j=0; j<_variableNames.length; j++) {
            variables.put(_variableNames[j], _variableValues[variation][j]);
        }
        return execute(variables);
    }
    
    private TestResult execute(Map variables) throws IOException {
        Object[] o = _test.get( WebApplicationTest.MMB_CONNECTION);
        Envelope[] conns = new Envelope[o.length];
        for (int z=0; z<o.length; z++) { conns[z] = (Envelope) o[z]; }
        
        TestResult result = null;
        for (int i=0; i<conns.length; i++) {
            String scheme = (String) conns[i].get( Connection.MMB_SCHEME, 0);
            String host = (String) conns[i].get( Connection.MMB_HOST, 0);
            String port = (String) conns[i].get( Connection.MMB_PORT, 0);
            String base = scheme + "://" + host + ":" + port;
            
            o = conns[i].get( Connection.MMB_STEP );
            Envelope[] steps = new Envelope[o.length];
            for (int z=0; z<o.length; z++) { steps[z] = (Envelope) o[z]; }
            
            URLFetcher uf = new URLFetcher();
            for (int j=0; j<steps.length; j++) {
                Envelope request = (Envelope) steps[j].get( Step.MMB_REQUEST, 0); // there can be only one ;-)
                org.owasp.webscarab.model.Request req = buildRequest(base, request, variables);
                org.owasp.webscarab.model.Response resp = uf.fetchResponse(req);
                
                Envelope response = (Envelope) steps[j].get( Step.MMB_RESPONSE, 0 );
                updateVariables(response, resp, variables);
                
                o = steps[j].get( Step.MMB_TESTCRITERIA );
                Envelope[] criteria = new Envelope[o.length];
                for (int z=0; z<o.length; z++) { criteria[z] = (Envelope) o[z]; }
                
                result = testCriteria(criteria, variables);
                // we actually need to specify whether we report on success or failure in the description
                if (result.isError() || result.isFailure()) { 
                    return result;
                }
            }
        }
        return result;
    }
    
    private org.owasp.webscarab.model.Request buildRequest(String base, Envelope request, Map variables) {
        // FIXME : we still need to consider the specified encoding in the various places
        
        org.owasp.webscarab.model.Request req = new org.owasp.webscarab.model.Request();
        Envelope messageHeader = (Envelope) request.get( Request.MMB_MESSAGEHEADER, 0 );
        
        Envelope e = (Envelope) messageHeader.get( MessageHeader.MMB_METHOD, 0 );
        String method = (String) e.get( Method.MMB_PCDATA, 0 );
        e = (Envelope) messageHeader.get( MessageHeader.MMB_URI, 0 );
        String uri = base + (String) e.get( URI.MMB_PCDATA, 0);
        e = (Envelope) messageHeader.get( MessageHeader.MMB_VERSION, 0 );
        String version = (String) e.get( Version.MMB_PCDATA, 0);
        
        req.setMethod(interpolate(method, variables));
        uri = interpolate(uri, variables);
        try {
            req.setURL(uri);
        } catch (MalformedURLException mue) {
            System.err.println("Tried to create a malformed URL! (" + uri + ") : " + mue);
            return null;
        }
        req.setVersion(interpolate(version, variables));
        
        Object[] o = messageHeader.get( MessageHeader.MMB_HEADER );
        Envelope[] headers = new Envelope[o.length];
        for (int z=0; z<o.length; z++) { headers[z] = (Envelope) o[z]; }
        
        for (int i=0; i<headers.length; i++) {
            Envelope h = (Envelope) headers[i].get( Header.MMB_NAME, 0 );
            String name = (String) h.get( Name.MMB_PCDATA, 0 );
            h = (Envelope) headers[i].get( Header.MMB_VALUE, 0 );
            String value = interpolate((String) h.get( Value.MMB_PCDATA, 0 ), variables);
            req.addHeader(name, value);
        }
        
        return req;
    }
    
    private void updateVariables(Envelope response, org.owasp.webscarab.model.Response resp, Map variables) {
        Object[] o = response.get( Response.MMB_SETVARIABLE );
        Envelope[] setvar = new Envelope[o.length];
        for (int z=0; z<o.length; z++) { setvar[z] = (Envelope) o[z]; }

        for (int i=0; i<setvar.length; i++) {
            String name = (String) setvar[i].get( SetVariable.MMB_NAME, 0 );
            Envelope e = (Envelope) setvar[i].get( SetVariable.MMB_SOURCE, 0 );
            String source = (String) e.get( Source.MMB_SOURCE, 0);
            String regex = (String) e.get( Source.MMB_PCDATA, 0 );
            System.out.println("Set '" + name + "' from " + source + " matching '" + regex + "'");
            Pattern p = Pattern.compile(".*" + regex + ".*"); // FIXME : should we require better regex syntax in the XML file?
            CharSequence compare = null;
            if (source.equalsIgnoreCase("status")) {
                compare = resp.getVersion() + " " + resp.getStatusLine();
            } else if (source.equalsIgnoreCase("header")) {
                StringBuffer sb = new StringBuffer();
                String[][] headers = resp.getHeaders();
                for (int h=0; h<headers.length; h++) {
                    sb.append(headers[h][0] + ": " + headers[h][1] + "\n");
                }
                compare = sb;
            } else if (source.equalsIgnoreCase("body")) {
                byte[] content = resp.getContent();
                if (content != null) {
                    compare = new String(content);
                }
            }
            if (compare != null) {
                Matcher m = p.matcher(compare);
                int count = m.groupCount();
                if (m.matches()) {
                    System.out.println("Matched " + count);
                    if (count < 1) {
                        variables.put(name, "");
                    } else {
                        String value = m.group(1);
                        System.out.println("matched '" + regex + "' = '" + value + "'");
                        variables.put(name, value);
                    }
                } else {
                    variables.put(name, "");
                }
            } else {
                System.err.println("Don't know how to match against '" + source + "'");
            }
        }
    }
    
    private TestResult testCriteria(Envelope[] criteria, Map variables) {
        for (int i=0; i<criteria.length; i++) {
            
            String type = (String) criteria[i].get( TestCriteria.MMB_TYPE, 0 );
            String message = (String) criteria[i].get( TestCriteria.MMB_ERRORMESSAGE, 0 );
            if (message == null) {
                message = "";
            }
            
            Object[] o = criteria[i].get( TestCriteria.MMB_COMPARE );
            Envelope[] compare = new Envelope[o.length];
            for (int z=0; z<o.length; z++) { compare[z] = (Envelope) o[z]; }
            
            if (compare(compare, variables)) {
                return new TestResult(type, message);
            }
            
        }
        return new TestResult(TestResult.FAILURE, "None of the criteria evaluated successfully");
    }
    
    private boolean compare(Envelope[] compare, Map variables) {
        boolean result = false;
        for (int i=0; i<compare.length; i++) {
            String variable = (String) compare[i].get( Compare.MMB_VARIABLE, 0 );
            variable = interpolate(variable, variables);
            String test = (String) compare[i].get( Compare.MMB_TEST, 0 );
            Envelope e = (Envelope) compare[i].get( Compare.MMB_VALUE, 0 );
            String value = (String) e.get( Value.MMB_PCDATA, 0 );
            if (value == null) {
                value = "";
            }
            if (test.equalsIgnoreCase("eq")) {
                result = variable.equals(value);
            } else if (test.equalsIgnoreCase("neq")) {
                result = !variable.equals(value);
            } else {
                System.err.println("Haven't implemented test type '" + test + "'");
            }
            if (result) {
                Object[] o = compare[i].get( Compare.MMB_COMPARE );
                if (o != null && o.length>0) {
                    Envelope[] children = new Envelope[o.length];
                    for (int z=0; z<o.length; z++) { children[z] = (Envelope) o[z]; }
                    result = compare(children, variables);
                }
            }
            if (result) {
                return true;
            }
        }
        return false;
    }
    
    private String interpolate(String str, Map variables) {
        StringBuffer sb = new StringBuffer();
        int start = str.indexOf("${");
        int end = -1;
        String var;
        while (start>-1) {
            sb.append(str.substring(end+1, start));
            end = str.indexOf("}", start);
            if (end < start) {
                System.err.println("Error interpolating! unmatched '${' after " + start);
                sb.append(str.substring(start));
                return sb.toString();
            }
            var = str.substring(start + 2, end);
            if (variables.get(var) != null) {
                sb.append((String) variables.get(var));
            } else {
                System.err.println("Undefined variable '" + var + "'. Replacing it with ''");
            }
            start = str.indexOf("${", end+1);
        }
        sb.append(str.substring(end+1));
        return sb.toString();
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 2) {
            URL url = null;
            try {
                url = new URL(args[0]);
            } catch (MalformedURLException mue) {
                System.err.println("Malformed URL " + mue);
                System.exit(1);
            }
            WASExecutor we = null;
            try {
                FileInputStream fis = new FileInputStream(args[1]);
                Node node = VulnFactory.slurp(fis);
                we = new WASExecutor(node, url);
                System.out.println("test has " + we.getVariations() + " variations");
            } catch (IOException ioe) {
                System.err.println("Error reading the test from " + args[0]);
                System.exit(1);
            }
            if (we != null) {
                try {
                    TestResult[] results = we.execute();
                    if (results.length>0) {
                        for (int i=0; i<results.length; i++) {
                            System.out.println(i + ": " + results[i].isSuccess() + " - " + results[i].getMessage());
                        }
                    }
                } catch (IOException ioe) {
                    System.out.println("IOException executing the test: " + ioe);
                }
            }
        } else {
            System.out.println("Usage: WASExecutor http://host:port/path/file test.xml");
            System.exit(1);
        }
    }
    
}
