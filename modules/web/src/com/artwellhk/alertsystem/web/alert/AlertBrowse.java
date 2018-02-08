package com.artwellhk.alertsystem.web.alert;

import java.util.Date;
import java.util.Map;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.artwellhk.alertsystem.entity.*;
import com.artwellhk.alertsystem.web.myDatasource.AlertListDatasource;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.gui.WindowManager;
import com.haulmont.cuba.gui.components.AbstractWindow;
import com.haulmont.cuba.gui.components.Component;
import com.haulmont.cuba.gui.components.Table;
import com.haulmont.cuba.gui.components.Timer;

public class AlertBrowse extends AbstractWindow {
	Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
	private Logger log = LoggerFactory.getLogger(AlertBrowse.class);
	@Inject
	private AlertListDatasource alertsDs;

//	@Override
//	public void init(Map<String, Object> params) {
//		alertsDs.setMaxResults(50);// 一页锟斤拷示锟斤拷锟斤拷锟斤拷锟斤拷录
//	}

	@Inject
	protected Table<Alert> alertsTable;

    public void setSnooze(Component source) {
    	Alert alert = alertsTable.getSingleSelected();
    	log.debug(gson.toJson(alert.getAlertType()));
    	AlertSnooze alertSnooze=new AlertSnooze();
		alertSnooze.setAlertType(alert.getAlertType());
		alertSnooze.setSampleOrderId(alert.getSampleOrder().getId());
		openEditor("alertsystem$AlertSnooze.edit",alertSnooze,WindowManager.OpenType.THIS_TAB)
		.addCloseWithCommitListener(() -> alertsDs.refresh());
		
    }
    
    public void refreshData(Timer timer) {
    	log.debug("Timer is runing:"+new Date());
    	alertsDs.refresh();
    }
}