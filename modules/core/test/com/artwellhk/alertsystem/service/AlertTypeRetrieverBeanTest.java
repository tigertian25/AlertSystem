package com.artwellhk.alertsystem.service;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.artwellhk.alertsystem.entity.Alert;
import com.artwellhk.alertsystem.entity.Process;
import com.artwellhk.alertsystem.entity.SampleOrder;

public class AlertTypeRetrieverBeanTest extends AlertTypeRetrieverBean {

	Boolean isHuaHuaSend = false;
	Boolean isHuaHuaReceive = false;
	Boolean isDianJiSend = false;
	Boolean isOtherReceive = false;
	Boolean hasOtherNext = false;

	@Override
	protected Alert GongYiNoReceive(SampleOrder sampleOrder) {
		if (sampleOrder.getIsReceive() == 1) {
			Alert alert = new Alert();
			alert.setEmployeeName("工艺未收回");
			return alert;
		}
		return null;

	}

	@Override
	protected Alert huaHuaNoSend(Map<String, Object> nextProcess, SampleOrder sampleOrder) {
		if (!isHuaHuaSend) {
			
			Alert alert = new Alert();
			alert.setEmployeeName("画花未发出");
			return alert;

		}
		return null;

	}

	@Override
	protected Alert huaHuaNoReceive(Map<String, Object> thisProcess, SampleOrder sampleOrder) {
		if (!isHuaHuaReceive) {
			Alert alert = new Alert();
			alert.setEmployeeName("画花未收回");
			return alert;

		}
		return null;
	}

	@Override
	protected Alert DianJiNoSend(Map<String, Object> thisProcess, Map<String, Object> nextProcess,
			SampleOrder sampleOrder) {
		if (!isDianJiSend) {
			Alert alert = new Alert();
			alert.setEmployeeName("电机未发出");
			return alert;
		}
		return null;
	}
	@Override
	protected Alert otherProcessNoReceive(Map<String, Object> thisProcess,SampleOrder sampleOrder,Process process) {
		if (!isOtherReceive) {
			Alert alert = new Alert();
			alert.setEmployeeName("电机或其他发出未收回");
			return alert;
		}
		return null;
	}
	@Override
	protected Alert otherNextProcessNoSend(Map<String, Object> thisProcess,SampleOrder sampleOrder,Process process) {
		if (!hasOtherNext) {
			Alert alert = new Alert();
			alert.setEmployeeName("电机或其他发出已收回，但下一工序未发出");
			return alert;
		}
		return null;
		
	}
	@Override
	public Map<String, Object> selectOneMapByParameter(String sqlname, Map<String, Object> parameter) {
		Map<String, Object> returnMap = new HashMap<>();
		returnMap.put("return", "selectOneMapByParameter return");
		returnMap.put("deptId", 1);
		return returnMap;
	}
	@Override
	protected Process getProcess(Integer deptId) {
		Process process = new Process();
		// TODO set process
		return process;
	}

	@Test
	public void testRetrieveList() {
		List<SampleOrder> sampleOrders = new ArrayList<SampleOrder>();
		SampleOrder sampleOrder = new SampleOrder();
		sampleOrder.setIsReceive(1);
		sampleOrders.add(sampleOrder);

		List<Alert> alerts_GongYiNoRec = retrieveList(sampleOrders);
		assertEquals("工艺未收回",alerts_GongYiNoRec.get(0).getEmployeeName());

		sampleOrders.get(0).setIsReceive(3);
		List<Alert> alerts_HuaHuaNoSend = retrieveList(sampleOrders);
		assertEquals("画花未发出",alerts_HuaHuaNoSend.get(0).getEmployeeName());

		isHuaHuaSend = true;
		List<Alert> alerts_HuaHuaNoRec = retrieveList(sampleOrders);
		assertEquals("画花未收回",alerts_HuaHuaNoRec.get(0).getEmployeeName());
		
		isHuaHuaReceive=true;
		List<Alert> alerts_DianJiNoSend = retrieveList(sampleOrders);
		assertEquals("电机未发出",alerts_DianJiNoSend.get(0).getEmployeeName());
		
		isDianJiSend=true;
		List<Alert> alerts_OtherNoRec = retrieveList(sampleOrders);
		assertEquals("电机或其他发出未收回",alerts_OtherNoRec.get(0).getEmployeeName());
		
		isOtherReceive=true;
		List<Alert> alerts_OtherNextNoSend = retrieveList(sampleOrders);
		assertEquals("电机或其他发出已收回，但下一工序未发出",alerts_OtherNextNoSend.get(0).getEmployeeName());
		
		//所有工序已完成
		hasOtherNext=true;
		List<Alert> alerts_OtherNextSend = retrieveList(sampleOrders);
		assertEquals(0,alerts_OtherNextSend.size());

	}

}
