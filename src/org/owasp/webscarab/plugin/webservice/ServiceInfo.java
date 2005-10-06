/*
 * All sample code contained herein is provided to you "AS IS" without any warranties of any kind.
 */
package org.owasp.webscarab.plugin.webservice;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * Service Info an in memory representation of a service defined in WSDL
 *
 * @author Jim Winfield
 */

public class ServiceInfo
{
   /** The service name */
   String name = "";

   /** The list of operations that this service defines. */
   List operations = new ArrayList();

   /**
    * Constructor
    */
   public ServiceInfo()
   {
   }

   /**
    * Sets the name of the service
    *
    * @param value The name of the service
    */
   public void setName(String value)
   {
      name = value;
   }

   /**
    * Gets the name of the service
    *
    * @return The name of the service is returned
    */
   public String getName()
   {
      return name;
   }

   /**
    * Add an ooperation info object to this service definition
    *
    * @param operation The operation to add to this service definition
    */
   public void addOperation(OperationInfo operation)
   {
      operations.add(operation);
   }

   /**
    * Returs the operations defined by this service
    *
    * @return an Iterator that can be used to iterate the operations defined by this service
    */
   public Iterator getOperations()
   {
      return operations.iterator();
   }

   /**
    * Override toString to return the name of the service
    *
    * @return The name of the service is returned
    */
   public String toString()
   {
      return getName();
   }
}
