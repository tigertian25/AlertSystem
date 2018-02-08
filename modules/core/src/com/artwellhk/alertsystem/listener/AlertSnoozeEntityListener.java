package com.artwellhk.alertsystem.listener;

import org.springframework.stereotype.Component;
import com.haulmont.cuba.core.listener.BeforeInsertEntityListener;
import com.haulmont.cuba.core.EntityManager;
import com.artwellhk.alertsystem.entity.AlertSnooze;

@Component("alertsystem_AlertSnoozeEntityListener")
public class AlertSnoozeEntityListener implements BeforeInsertEntityListener<AlertSnooze> {


    @Override
    public void onBeforeInsert(AlertSnooze entity, EntityManager entityManager) {
    	
    	entity.setDuration(entity.getDuration()*60*1000);//分钟转化成毫秒
    }


}