package com.artwellhk.alertsystem.service;


import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.persistence.NoResultException;

import org.apache.ibatis.session.SqlSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.artwellhk.alertsystem.entity.Alert;
import com.artwellhk.alertsystem.entity.AlertType;
import com.artwellhk.alertsystem.entity.Process;
import com.artwellhk.alertsystem.entity.ProcessIdEnum;
import com.artwellhk.alertsystem.entity.ProcessType;
import com.artwellhk.alertsystem.entity.SampleOrder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.global.AppBeans;

@Service(AlertTypeRetrieverService.NAME)
public class AlertTypeRetrieverBean implements AlertTypeRetrieverService {
	Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
	private Logger log = LoggerFactory.getLogger(AlertTypeRetrieverBean.class);
	@Inject
	private Persistence persistence;
	
	
	@Override
	public List<Alert> retrieveList(List<SampleOrder> sampleOrderList) {
		List<Alert> alertList =  new LinkedList<Alert>();
		if (sampleOrderList.isEmpty()) {
			return alertList;
		}
		// 循环sampleOrderList
		for (SampleOrder sampleOrder : sampleOrderList) {
				
				Map<String, Object> thisProcess = null;// 当前工序
				Map<String, Object> nextProcess = null;// 下一工序
				Map<String, Object> parameter = new HashMap<>();
				parameter.put("styleID", sampleOrder.getId());

				// 工艺未收回：isReceive=1表示未收回，2表示已收回
				Alert alert=GongYiNoReceive(sampleOrder);
				if(null!=alert) {
					alertList.add(alert);
					continue;
				}
				
				// 画花未发出
				nextProcess = selectOneMapByParameter("ERPDBMapper.getHuaHuaSend", parameter);
				alert=huaHuaNoSend(nextProcess,sampleOrder);
				if(null!=alert) {
					alertList.add(alert);
					continue;
				}

				//画花未收回
				thisProcess = nextProcess;//当前工序为画花已发出
				alert=huaHuaNoReceive(thisProcess,sampleOrder);
				if(null!=alert) {
					alertList.add(alert);
					continue;
				}

				//电机未发出
				nextProcess = selectOneMapByParameter("ERPDBMapper.getIssue60ByStyleID", parameter);// 查询最后收发时间
				alert=DianJiNoSend(thisProcess,nextProcess,sampleOrder);
				if(null!=alert) {
					alertList.add(alert);
					continue;
				}

				// 有工序发出
				thisProcess = nextProcess;
				
				// 根据deptId查出当前发出工序是什么
				Process process = getProcess(Integer.parseInt(thisProcess.get("deptId").toString()));
				if (null == process) {
					continue;
				}
				
				//电机或其他工序发出未收回
				alert=otherProcessNoReceive(thisProcess,sampleOrder,process);
				if(null!=alert) {
					alertList.add(alert);
					continue;
				}

				//电机或其他工序发出已收回，判断是否有下一工序，（如果有下一工序，表示下一工序未发出），（如果有下一工序，表示所有工序已完成）
				alert=otherNextProcessNoSend(thisProcess,sampleOrder,process);
				if(null!=alert) {
					alertList.add(alert);
					continue;
				}
				
		}
			
		return alertList;
	}
	/**
	 * 查询AlertType
	 * @param fromProcessId
	 * @param fromProcessType
	 * @return AlertType
	 */
	private AlertType getAlertType(int fromProcessId,int fromProcessType) {
		AlertType alertType = null;
		try (Transaction tx = persistence.createTransaction()) {
			EntityManager em = persistence.getEntityManager();
			alertType = (AlertType) em.createQuery(
					"select distinct a from alertsystem$AlertType a JOIN FETCH a.fromProcess f JOIN FETCH a.toProcess t where"
							+ " f.id= :fromProcessId"
							+ " and a.fromProcessType=:fromProcessType"
							)
					.setParameter("fromProcessId", fromProcessId)
					.setParameter("fromProcessType", fromProcessType)
					.getSingleResult();
			tx.commit();
		} catch (NoResultException e) {
			return null;
		}
		return alertType;
		
	}
	


	/**
	 * 根据参数查询一条数据
	 * @param sqlname mybatis对应的映射名:ERPDBMapper.getHuaHuaSend
	 * @param parameter 参数
	 * @return map
	 */
	public Map<String, Object> selectOneMapByParameter(String sqlname, Map<String, Object> parameter) {
		Map<String, Object> returnMap = null;

		Transaction tx = persistence.createTransaction("ERPDB");
		try {
			SqlSession sqlSession = AppBeans.get("sqlSession_ERPDB");
			returnMap = sqlSession.selectOne(sqlname, parameter);
			tx.commit();

		} catch (NoResultException e) {
			return null;
		} finally {
			tx.end();
		}
		return returnMap;
	}
	
	/**
	 * 根据deptId查出当前发出工序是什么
	 * @param deptId
	 * @return Process
	 */
	protected Process getProcess(Integer deptId) {
	Process process = null;
	try (Transaction tx = persistence.createTransaction()) {// 根据deptId查出当前发出工序是什么
		EntityManager em = persistence.getEntityManager();
		process = (Process) em.createQuery(
						"select o from alertsystem$Process o where o.deptId = :deptId")
				.setParameter("deptId", deptId).getFirstResult();
		tx.commit();
	} catch (NoResultException e) {
		
		return null;
	}
		return process;
	
	}
	
/**
 * 工艺未收回
 * @param sampleOrder
 * @return Alert
 */
	protected Alert GongYiNoReceive(SampleOrder sampleOrder) {
		if (sampleOrder.getIsReceive() == 1) {

			AlertType alertType=getAlertType(ProcessIdEnum.GongYi.getId(), ProcessType.send.getId());
			if(null!=alertType) {
				Alert alert = new Alert(alertType, sampleOrder);
				alert.setEmployeeName(sampleOrder.getGongYiSendEmpl());
				alert.setFromTimestamp(sampleOrder.getGongYiSendTime());
				return alert;
			}
		}
		return null;
	}
/**
 * 画花未发出
 * @param nextProcess 下一工序
 * @param sampleOrder 当前订单信息
 * @return Alert
 */
	protected Alert huaHuaNoSend(Map<String, Object> nextProcess,SampleOrder sampleOrder) {
		
		if (null == nextProcess) {//画花未发出

			AlertType alertType=getAlertType(ProcessIdEnum.GongYi.getId(), ProcessType.receive.getId());
			if(null!=alertType) {
				Alert alert = new Alert(alertType, sampleOrder);
				alert.setEmployeeName(sampleOrder.getGongYiSendEmpl());
				alert.setFromTimestamp(sampleOrder.getGongYiReceiveTime());
				return alert;
			}
		}
		return null;
	}
/**
 * 画花未收回
 * @param thisProcess 当前工序
 * @param sampleOrder 当前订单
 * @return Alert
 */
	protected Alert huaHuaNoReceive(Map<String, Object> thisProcess,SampleOrder sampleOrder) {
		int huahuaIsReceive=Integer.parseInt(thisProcess.get("isReceive").toString());
		if(huahuaIsReceive==1) {//isReceive=1表示未收回，2表示已收回

			AlertType alertType=getAlertType(ProcessIdEnum.HuaHua.getId(), ProcessType.send.getId());
			if(null!=alertType) {
				Alert alert = new Alert(alertType, sampleOrder);
				alert = new Alert(alertType, (Date)thisProcess.get("fromTimestamp"), sampleOrder,
						thisProcess.get("employeeName").toString());
				return alert;
			}
		}
		return null;
	}
/**
 * 电机未发出
 * @param thisProcess 当前工序
 * @param nextProcess 下一工序
 * @param sampleOrder 当前订单
 * @return Alert
 */
	protected Alert DianJiNoSend(Map<String, Object> thisProcess,Map<String, Object> nextProcess,SampleOrder sampleOrder) {
		
		if (null == nextProcess) {// 表示电机未发出

			AlertType alertType=getAlertType(ProcessIdEnum.HuaHua.getId(), ProcessType.receive.getId());
			if(null!=alertType) {
				Alert alert = new Alert(alertType, sampleOrder);
				alert = new Alert(alertType, (Date) thisProcess.get("toTimestamp"), sampleOrder,
						thisProcess.get("employeeName").toString());
				return alert;
			}
		}
		return null;
	}

	/**
	 * 电机或其他工序发出未收回
	 * @param thisProcess 当前工序
	 * @param sampleOrder 当前订单
	 * @param process 当前工序对应的process
	 * @return Alert
	 */
	protected Alert otherProcessNoReceive(Map<String, Object> thisProcess,SampleOrder sampleOrder,Process process) {
		if ("1".equals(thisProcess.get("aStatus").toString())) {// aStatus=1当前工序发出未收回

			// 根据当前工序的process.getId()查询AlertType
			AlertType alertType = null;
			try (Transaction tx = persistence.createTransaction()) {
				EntityManager em = persistence.getEntityManager();
				alertType = (AlertType) em.createQuery(
						"select distinct a from alertsystem$AlertType a JOIN FETCH a.fromProcess f JOIN FETCH a.toProcess t where a.fromProcessType="+ProcessType.send.getId()
								+ " and f.id= :id")
						.setParameter("id", process.getId()).getFirstResult();
				tx.commit();
			} catch (NoResultException e) {
				return null;
			}
			
			if (null != alertType) {
				Alert alert = new Alert(alertType, (Date)thisProcess.get("sendTime"),
						sampleOrder, thisProcess.get("sendEmployee").toString());
				return alert;
			}
		}
		return null;
	}
/**
 * 电机或其他工序发出已收回，下一工序未发出
  * @param thisProcess 当前工序
  * @param sampleOrder 当前订单
  * @param process 当前工序对应的process
  * @return Alert
 */
	protected Alert otherNextProcessNoSend(Map<String, Object> thisProcess,SampleOrder sampleOrder,Process process) {
		if ("3".equals(thisProcess.get("aStatus").toString())) {// aStatus=3当前工序发出并已经收回
			// 查询下一工序
			AlertType alertType = null;

				try (Transaction tx = persistence.createTransaction()) {
					EntityManager em = persistence.getEntityManager();
					alertType = (AlertType) em.createQuery(
							"select distinct a from alertsystem$AlertType a JOIN FETCH a.fromProcess f JOIN FETCH a.toProcess t where a.fromProcessType="+ProcessType.receive.getId()
									+ " and f.id= :id order by a.id desc")
							.setParameter("id", process.getId()).getFirstResult();
					tx.commit();
				} catch (NoResultException e) {
					return null;
				}
				if (null != alertType) {//表示有下一工序，即当前工序不是最后工序
					Alert alert = new Alert(alertType, (Date)thisProcess.get("receiveTime"),
							sampleOrder, thisProcess.get("receiveName").toString());
					return alert;
				}
		}
		return null;
	}

}
