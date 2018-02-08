package com.artwellhk.alertsystem.web.alerttype;


import com.haulmont.cuba.gui.components.Formatter;

public class MyFormatter  implements Formatter<Object>{
	

	    @Override
	    public String format(Object value) {
	    	if(null!=value) {
		    	int val=Integer.parseInt(value.toString());
		    	val=val/60/1000;
		    	return Integer.toString(val);
	    	}else {
	    		return null;
	    	}
	    }
	
}
