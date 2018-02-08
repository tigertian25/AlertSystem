package com.artwellhk.alertsystem.service;

import java.util.List;

import com.artwellhk.alertsystem.entity.Alert;
import com.artwellhk.alertsystem.entity.SampleOrder;

public interface  AlertTypeRetrieverService {
	public static final String NAME = "alertsystem_AlertTypeRetrieverService";
	//筛选出工序未完成的版单
    public List<Alert> retrieveList(List<SampleOrder> SampleOrderList) ;

}
