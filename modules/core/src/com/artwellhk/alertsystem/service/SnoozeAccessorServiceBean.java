package com.artwellhk.alertsystem.service;


import javax.inject.Inject;
import javax.persistence.NoResultException;

import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.artwellhk.alertsystem.entity.AlertSnooze;
import com.artwellhk.alertsystem.entity.AlertType;
import com.artwellhk.alertsystem.entity.ReturnMsg;
import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.global.CommitContext;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.core.global.Metadata;

@Service(SnoozeAccessorService.NAME)
public class SnoozeAccessorServiceBean implements SnoozeAccessorService {
	@Inject
	private Persistence persistence;
	@Inject
	private Metadata metadata;
	@Inject
    private DataManager dataManager;
	

	@Override
	public AlertSnooze getSnooze(int sampleOrderId, int alertTypeId) {
		AlertSnooze alertSnooze = new AlertSnooze();
		try (Transaction tx = persistence.createTransaction()) {
			EntityManager em = persistence.getEntityManager();
			alertSnooze = (AlertSnooze) em
					.createQuery("select a from alertsystem$AlertSnooze a JOIN FETCH a.alertType t where"
							+ " a.sampleOrderId= :sampleOrderId and t.id = :alertTypeId order by a.createTs desc")
					.setParameter("sampleOrderId", sampleOrderId).setParameter("alertTypeId", alertTypeId)
					.getFirstResult();
			tx.commit();
		}
		return alertSnooze;
	}

	

}
