package com.artwellhk.alertsystem.service;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.ClassRule;
import org.junit.Test;

import com.artwellhk.alertsystem.AlertsystemTestContainer;
import com.artwellhk.alertsystem.entity.AlertSnooze;
import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.core.global.Metadata;

public class SnoozeAccessorServiceBeanTest {
	 @ClassRule
	    public static AlertsystemTestContainer cont = AlertsystemTestContainer.Common.INSTANCE;

	    private Metadata metadata;
	    private Persistence persistence;
	    private DataManager dataManager;
	@Test
	public void testGetSnooze() {
		int sampleOrderId=531411193;
		int alertTypeId=201;
		List<AlertSnooze> alertSnooze = new ArrayList<>();
		try (Transaction tx = persistence.createTransaction()) {
			EntityManager em = persistence.getEntityManager();
			alertSnooze = em
					.createQuery("select a from alertsystem$AlertSnooze a JOIN FETCH a.alertType t where"
							+ " a.sampleOrderId= :sampleOrderId and t.id = :alertTypeId order by a.createTs desc")
					.setParameter("sampleOrderId", sampleOrderId).setParameter("alertTypeId", alertTypeId)
					.getResultList();
			tx.commit();
		}
		 assertEquals(1, alertSnooze.size());
	}

	

}
