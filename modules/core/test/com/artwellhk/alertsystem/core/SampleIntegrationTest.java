package com.artwellhk.alertsystem.core;

import com.artwellhk.alertsystem.AlertsystemTestContainer;
import com.artwellhk.alertsystem.AlertsystemTestContainerERPDB;
import com.artwellhk.alertsystem.entity.AlertSnooze;
import com.artwellhk.alertsystem.entity.AlertType;
import com.artwellhk.alertsystem.entity.Process;
import com.artwellhk.alertsystem.entity.SampleOrder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.TypedQuery;
import com.haulmont.cuba.core.global.AppBeans;
import com.haulmont.cuba.core.global.CommitContext;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.core.global.Metadata;
import com.haulmont.cuba.security.entity.User;

import org.apache.ibatis.session.SqlSession;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.NoResultException;

import static org.junit.Assert.assertEquals;

public class SampleIntegrationTest {

    @ClassRule
    public static AlertsystemTestContainer cont = AlertsystemTestContainer.Common.INSTANCE;

    private Metadata metadata;
    private Persistence persistence;
    private DataManager dataManager;
//    @ClassRule
//    public static AlertsystemTestContainerERPDB contERPDB = AlertsystemTestContainerERPDB.Common.INSTANCE;

//    private Metadata metadataERPDB;
//    private Persistence persistenceERPDB;

    @Before
    public void setUp() throws Exception {
        metadata = cont.metadata();
        persistence = cont.persistence();
        dataManager = AppBeans.get(DataManager.class);
        
//        metadataERPDB = contERPDB.metadata();
//        persistenceERPDB = contERPDB.persistence();
    }

    @After
    public void tearDown() throws Exception {
    }
    @Test
  public void testLoadUser() {
    List<AlertType> alertType;
	 try (Transaction tx = persistence.createTransaction()) {
           EntityManager em = persistence.getEntityManager();
           alertType =  em.createQuery("select e.fromProcess,e.fromProcessType,e.toProcess,e.toProcessType,e.allowedDuration/60/1000,e.id from alertsystem$AlertType e")
           		.getResultList();
           tx.commit();
       } catch(NoResultException e) {
           return ;
       }
	 String processListJsonString=gson.toJson(alertType);
     System.out.println(processListJsonString);
    }
//    @Test
//    public void testLoadUser() {
//        try (Transaction tx = persistence.createTransaction()) {
//            EntityManager em = persistence.getEntityManager();
//            TypedQuery<User> query = em.createQuery(
//                    "select u from sec$User u where u.login = :userLogin", User.class);
//            query.setParameter("userLogin", "admin");
//            List<User> users = query.getResultList();
//            tx.commit();
//            assertEquals(1, users.size());
//        }
//    }
    Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
//    @Test
//	public void testMybatis() {
//		Transaction tx = persistence.createTransaction();
//		com.artwellhk.alertsystem.entity.Process process;
//		try {
//		  SqlSession sqlSession = AppBeans.get("sqlSession");
//		  Map<String, Object> map=new HashMap<>();
//		  map.put("ztWorkingId", 2);
//		  Object obj=   sqlSession.selectOne("ERPDBMapper.getProcess",map);
//		  process=(Process) obj;
//		  tx.commit();
//		} finally {
//		  tx.end();
//		}
//		  String processListJsonString=gson.toJson(process);
//	        System.out.println(processListJsonString);
//	}
//    @Test
//   	public void testInsert() {
//    	
//    	AlertType alertType = new AlertType();
//    	try (Transaction tx = persistence.createTransaction()) {
//			EntityManager em = persistence.getEntityManager();
//			alertType = (AlertType) em.createQuery(
//					"select distinct a from alertsystem$AlertType a JOIN FETCH a.fromProcess f JOIN FETCH a.toProcess t "
//							+ " where a.id=:id order by a.id desc")
//					.setParameter("id", 1)
//					.getFirstResult();
//			tx.commit();
//		} catch (NoResultException e) {
//			return;
//		}
//    	AlertSnooze alertSnooze = metadata.create(AlertSnooze.class);
//		alertSnooze.setAlertType(alertType);
//		alertSnooze.setSampleOrderId(123456);
//		alertSnooze.setDuration(30*60);
//		dataManager.commit(new CommitContext(alertSnooze));
//    }
//    @Test
//    public void testMybatisERPDB() {
//    	List<SampleOrder> sampleOrderList;
//		try (Transaction tx = persistenceERPDB.createTransaction()) {
//			SqlSession sqlSession = AppBeans.get("sqlSession");
//			sampleOrderList = sqlSession.selectList("ERPDBMapper.getAllStyleOfGOngYiSend");
//			tx.commit();
//		} catch (NoResultException e) {
//			return;
//		}
//    	String jsonString=gson.toJson(sampleOrderList);
//    	System.out.println(jsonString);
//    }
  
}