package com.artwellhk.alertsystem.web.myDatasource;

import com.artwellhk.alertsystem.entity.Alert;
import com.artwellhk.alertsystem.entity.AlertType;
import com.artwellhk.alertsystem.entity.Process;
import com.artwellhk.alertsystem.entity.SampleOrder;
import com.artwellhk.alertsystem.service.AlertService;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.core.global.AppBeans;
import com.haulmont.cuba.gui.data.impl.CustomCollectionDatasource;
import com.haulmont.cuba.gui.data.impl.CustomGroupDatasource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import javax.inject.Inject;

import org.apache.commons.lang.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AlertListDatasource extends CustomCollectionDatasource<Alert, UUID> {
	@Inject
	AlertService alertService = AppBeans.get(AlertService.NAME);

	private Logger log = LoggerFactory.getLogger(AlertListDatasource.class);
	private Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
	
	@Override
	protected Collection<Alert> getEntities(Map<String, Object> params) {
		/*log.debug(gson.toJson(params));
		Collection<Alert> alertList = new ArrayList<Alert>();
		AlertType alertType = new AlertType(1, new Process(2, "工艺发出"), new Process(3, "工艺收回"), 60 * 30,1,2);
		Alert alert = new Alert(alertType, DateUtils.addSeconds(new Date(), -60 * 30 - 20), new SampleOrder(123456, "sp-123456","L123456"),"张三");
		alertList.add(alert);
		log.debug(gson.toJson(alertList));
		return alertList;*/
		Collection<Alert> alertList=alertService.calculateAlertList();
		return alertList;
	}
	 /*@Override
	    public int getCount() {
	        return this.getEntities(null).size();
	    }*/
}