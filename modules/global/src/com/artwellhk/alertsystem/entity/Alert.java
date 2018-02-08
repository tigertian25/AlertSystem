package com.artwellhk.alertsystem.entity;

import com.haulmont.chile.core.annotations.MetaClass;
import com.haulmont.chile.core.annotations.MetaProperty;

import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import com.haulmont.cuba.core.entity.BaseIntegerIdEntity;
import com.haulmont.cuba.core.entity.BaseUuidEntity;

import javax.validation.constraints.NotNull;
import com.haulmont.chile.core.annotations.NamePattern;
import java.util.UUID;
import com.haulmont.cuba.core.entity.HasUuid;

import freemarker.template.SimpleDate;

@NamePattern("%s %s %s %s %s %s|sampleOrder,alertType,employeeName,fromTimestamp,lastTimestamp,timeDifference")
@MetaClass(name = "alertsystem$Alert")
public class Alert extends BaseUuidEntity {
    private static final long serialVersionUID = 4543700162506865893L;

    @NotNull
    @MetaProperty(mandatory = true)
    protected AlertType alertType;

    @MetaProperty
    protected SampleOrder sampleOrder;

    @MetaProperty
    protected Date fromTimestamp;

    @MetaProperty
    protected Date lastTimestamp;

    @MetaProperty
    protected String timeDifference;

    @MetaProperty
    protected String employeeName;



    public void setSampleOrder(SampleOrder sampleOrder) {
        this.sampleOrder = sampleOrder;
    }

    public SampleOrder getSampleOrder() {
        return sampleOrder;
    }

    public void setTimeDifference(String timeDifference) {
        this.timeDifference = timeDifference;
    }

    public String getTimeDifference() {
        return timeDifference;
    }

    public void setEmployeeName(String employeeName) {
        this.employeeName = employeeName;
    }

    public String getEmployeeName() {
        return employeeName;
    }


    public void setLastTimestamp(Date lastTimestamp) {
    	if(null!=lastTimestamp) {
        try {
        	SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			lastTimestamp = formatter.parse(formatter.format(lastTimestamp));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	}
    	this.lastTimestamp=lastTimestamp;
    }

    public Date getLastTimestamp() {
    	if(null!=lastTimestamp) {
        try {
        	SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        	lastTimestamp= formatter.parse(formatter.format(lastTimestamp));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			return null;
		}}
        return lastTimestamp;
    }


    public void setAlertType(AlertType alertType) {
        this.alertType = alertType;
    }


    public AlertType getAlertType() {
        return alertType;
    }

    public void setFromTimestamp(Date fromTimestamp) {
    	if(null!=fromTimestamp) {
	        try {
	        	SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	        	fromTimestamp = formatter.parse(formatter.format(fromTimestamp));
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
    	this.fromTimestamp = fromTimestamp;
    }

    public Date getFromTimestamp() {
    	if(null!=fromTimestamp) {
	        try {
	        	SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	        	fromTimestamp= formatter.parse(formatter.format(fromTimestamp));
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
        return fromTimestamp;
    }
    public Alert() {}
	
	public Alert(AlertType alertType,Date fromTimestamp,SampleOrder sampleOrder,String employeeName) {
		this.alertType=alertType;
		if(null!=fromTimestamp) {
		try {
			SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			fromTimestamp=formatter.parse(formatter.format(fromTimestamp));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			return ;
		}}
		this.fromTimestamp=fromTimestamp;
		this.sampleOrder=sampleOrder;
		this.employeeName=employeeName;
	}
	public Alert(AlertType alertType,SampleOrder sampleOrder) {
		this.alertType=alertType;this.sampleOrder=sampleOrder;
	}
	 
	   
}