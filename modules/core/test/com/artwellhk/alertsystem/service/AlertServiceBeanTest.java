package com.artwellhk.alertsystem.service;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang.time.DateUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.artwellhk.alertsystem.entity.*;
import com.artwellhk.alertsystem.entity.Process;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.core.global.UuidProvider;

//设置睡眠并超过睡眠时间，或者没设置睡眠
public class AlertServiceBeanTest extends AlertServiceBean {
	Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
	private Logger log = LoggerFactory.getLogger(AlertServiceBeanTest.class);
	
	int isSetSnoozeTime = 1;// 1超过睡眠时间，2没超过睡眠时间
	UUID uid=UuidProvider.createUuid();
	
	@Override
	protected Alert isSetSnoozeTime(Alert alert, Date now, Date lastTimestamp) {
		if (isSetSnoozeTime == 2) {
			return null;
		}
		return alert;

	}

	@Override
	protected List<Alert> getAlertList() {
		List<Alert> alertList = new ArrayList<Alert>();
		AlertType alertType = new AlertType(1, new Process(2, "工艺"), new Process(3, "画花"), 60 * 30, 1, 2);
		Alert alert = new Alert(alertType, DateUtils.addSeconds(new Date(), -60 * 30 - 20),
				new SampleOrder(123456, "sp-123456", "L123456"), "寮犱笁");
		alert.setId(uid);
		alertList.add(alert);
		return alertList;

	}

	@Test
	public void testCalculateAlertList() {
		Collection<Alert> alertList = calculateAlertList();
		
		List<Alert> testAlertList = getAlertList();
		
		Alert alert=testAlertList.get(0);
		int allowedDuration = alert.getAlertType().getAllowedDuration();// 规定时限
		Date fromTimestamp = alert.getFromTimestamp();// 当前工序完成时间
		Date lastTimestamp = DateUtils.addSeconds(fromTimestamp, allowedDuration);// 预计下一工序完成时间
		alert.setLastTimestamp(lastTimestamp);

		assertEquals(testAlertList, alertList);

		isSetSnoozeTime = 2;
		alertList = calculateAlertList();
		assertEquals(0, alertList.size());

	}

}
