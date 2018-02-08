package com.artwellhk.alertsystem.service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.NoResultException;

import org.apache.commons.lang.time.DateUtils;
import org.apache.ibatis.session.SqlSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.artwellhk.alertsystem.core.util;
import com.artwellhk.alertsystem.entity.Alert;
import com.artwellhk.alertsystem.entity.AlertSnooze;
import com.artwellhk.alertsystem.entity.AlertType;
import com.artwellhk.alertsystem.entity.SampleOrder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.global.AppBeans;

@Service(AlertService.NAME)
public class AlertServiceBean implements AlertService {
	Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
	private Logger log = LoggerFactory.getLogger(AlertServiceBean.class);
	@Inject
	private Persistence persistence;
	@Inject
	private AlertTypeRetrieverService alertTypeRetriever;
	@Inject
	private SnoozeAccessorService snoozeAccessor;

	/**
	 * 判断超时的数据是否设置了睡眠 没设置睡眠，计算TimeDifference 如果设置了睡眠，判断有没有超过睡眠时间 没有超过睡眠时间，返回null，
	 * 超过随眠时间，修改TimeDifference
	 * 
	 * @param alert
	 * @param now
	 * @param lastTimestamp
	 * @return Alert
	 */
	protected Alert isSetSnoozeTime(Alert alert, Date now, Date lastTimestamp) {
		alert.setTimeDifference(util.dateUtil(now, lastTimestamp));

		AlertSnooze alertSnooze = snoozeAccessor.getSnooze(alert.getSampleOrder().getId(),
				alert.getAlertType().getId());
		if (null != alertSnooze) {// alertSnooze!= null 表示设置了睡眠
			Date durationDate = alertSnooze.getCreateTs();
			// snooze的创建时间加上设置的睡眠毫秒数等于睡眠时间
			Date snoozeTime = DateUtils.addMilliseconds(durationDate, alertSnooze.getDuration());
			// 没超过睡眠时间
			if (now.getTime() < snoozeTime.getTime()) {
				return null;
			}
			alert.setTimeDifference(util.dateUtil(now, snoozeTime));
		}

		setAlertTypeProcessInfo(alert.getAlertType());
		log.debug("isSetSnoozeTime=="+gson.toJson(alert));
		return alert;
	}

	@Override
	public Collection<Alert> calculateAlertList() {
		Collection<Alert> returnAlertList = new ArrayList<Alert>();
		List<Alert> alertList = getAlertList();

		if (alertList.isEmpty()) {
			return null;
		}
		for (Alert alert : alertList) {
			Date now = new Date();
			int allowedDuration = alert.getAlertType().getAllowedDuration();// 规定时限
			Date fromTimestamp = alert.getFromTimestamp();// 当前工序完成时间
			Date lastTimestamp = DateUtils.addMilliseconds(fromTimestamp, allowedDuration);// 预计下一工序完成时间
			alert.setLastTimestamp(lastTimestamp);
			// 如果当前时间大于预计下一工序完成时间，表示超时
			if (now.getTime() > lastTimestamp.getTime() && (now.getTime() - lastTimestamp.getTime()) > 1000) {
				if (null != (alert = isSetSnoozeTime(alert, now, lastTimestamp))) {
					returnAlertList.add(alert);
				}
			}
		}

		log.debug("returnAlertList:" + gson.toJson(returnAlertList));
		return returnAlertList;

	}

	private void setAlertTypeProcessInfo(AlertType alertType) {
		String fromInfo = "发出";
		String toInfo = "发出";
		if (2 == alertType.getFromProcessType().getId()) {
			fromInfo = "收回";
		}
		if (2 == alertType.getToProcessType().getId()) {
			toInfo = "收回";
		}
		alertType.setFromProcessInfo(alertType.getFromProcess().getName() + fromInfo);
		alertType.setToProcessInfo(alertType.getToProcess().getName() + toInfo);

	}

	protected List<Alert> getAlertList() {
		List<Alert> alertList = new LinkedList<Alert>();
		List<SampleOrder> sampleOrderList = new LinkedList<SampleOrder>();

		Transaction tx = persistence.createTransaction("ERPDB");
		try {
			SqlSession sqlSession = AppBeans.get("sqlSession_ERPDB");
			sampleOrderList = sqlSession.selectList("ERPDBMapper.getAllStyleOfGOngYiSend");

			tx.commit();
		} catch (NoResultException e) {
			e.printStackTrace();
		}
		alertList = alertTypeRetriever.retrieveList(sampleOrderList);
log.debug("getAlertList=="+gson.toJson(alertList));
		return alertList;

	}
}