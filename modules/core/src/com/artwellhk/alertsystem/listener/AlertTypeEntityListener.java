package com.artwellhk.alertsystem.listener;

import org.springframework.stereotype.Component;
import com.haulmont.cuba.core.listener.BeforeInsertEntityListener;
import com.haulmont.cuba.core.EntityManager;
import com.artwellhk.alertsystem.entity.AlertType;
import com.haulmont.cuba.core.listener.BeforeUpdateEntityListener;
import com.haulmont.cuba.core.listener.BeforeDetachEntityListener;

@Component("alertsystem_AlertTypeEntityListener")
public class AlertTypeEntityListener implements BeforeInsertEntityListener<AlertType>, BeforeUpdateEntityListener<AlertType>{


    @Override
    public void onBeforeInsert(AlertType entity, EntityManager entityManager) {
    	System.out.println("进入拦截器onBeforeInsert");
    	entity.setAllowedDuration(entity.getAllowedDuration()*60*1000);//分钟转化成毫秒

    }


    @Override
    public void onBeforeUpdate(AlertType entity, EntityManager entityManager) {
    	System.out.println("进入拦截器onBeforeUpdate");
    	System.out.println(entity.getAllowedDuration());
    	entity.setAllowedDuration(entity.getAllowedDuration()*60*1000);//分钟转化成毫秒
    }


    


}