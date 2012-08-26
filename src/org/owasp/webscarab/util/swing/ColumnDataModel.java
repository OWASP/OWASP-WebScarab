/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
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

/*
 * ColumnDataModel.java
 *
 * Created on 06 December 2004, 04:47
 */

package org.owasp.webscarab.util.swing;

import javax.swing.event.EventListenerList;

/**
 * Represents a column of data, which can be looked up using a specific
 * Object as a key
 * @author rogan
 */
public abstract class ColumnDataModel<T> {
    
    /**
     * Maintains the list of listeners
     */
    protected EventListenerList _listenerList = new EventListenerList();
    
    private String name = null;
    private Class<?> clazz = Object.class;
    
    /**
     * Creates a new ColumnDataModel
     */
    protected ColumnDataModel(String name, Class<?> clazz) {
    	this.name = name;
    	this.clazz = clazz;
    }
    /**
     * Used by the "composing" table model to determine what the class of the
     * column objects is.
     * @return the default class of objects in this column
     */
    public Class<?> getColumnClass() {
        return clazz;
    }
    
    /**
     * used to determine the name of this column
     * @return The name of the column
     */
    public String getColumnName() {
    	return name;
    }
    
    /**
     * Used to determine the value of the particular cell of the column,
     * corresponding to the supplied key object
     * @param key the "index" object
     * @return the value
     */
    public abstract Object getValue(T key);
    
    public boolean isEditable(T key) {
    	return false;
    }
    
    public void setValue(Object aValue, T key) {
    }
    
    /**
     * Adds a listener to the column model
     * @param l the listener to add
     */
    public void addColumnDataListener(ColumnDataListener<T> l) {
        _listenerList.add(ColumnDataListener.class, l);
    }
    
    /**
     * removes a listener from the column model
     * @param l the listener to remove
     */
    public void removeColumnDataListener(ColumnDataListener<T> l) {
        _listenerList.remove(ColumnDataListener.class, l);
    }
    
    // Notify all listeners that have registered interest for
    // notification on this event type.  The event instance
    // is lazily created using the parameters passed into
    // the fire method.
    
    /**
     * notifies listeners that a single value has changed, and that the composing
     * table should update its cells
     * @param key the index object that has changed
     */
    public void fireValueChanged(T key) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        ColumnDataEvent<T> columnEvent = null;
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ColumnDataListener.class) {
                // Lazily create the event:
                if (columnEvent == null)
                    columnEvent = new ColumnDataEvent<T>(this, key);
                ((ColumnDataListener)listeners[i+1]).dataChanged(columnEvent);
            }
        }
    }
    
    /**
     * notifies listeners that all values in the column have changed, and that the
     * composing table should update its cells
     */
    public void fireValuesChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        ColumnDataEvent<T> columnEvent = null;
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ColumnDataListener.class) {
                // Lazily create the event:
                if (columnEvent == null)
                    columnEvent = new ColumnDataEvent<T>(this, null);
                ((ColumnDataListener)listeners[i+1]).dataChanged(columnEvent);
            }
        }
    }
    
    public String toString() {
    	return getColumnName() + "[" + getColumnClass() + "]";
    }
}
