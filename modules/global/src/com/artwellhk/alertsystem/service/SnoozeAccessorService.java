package com.artwellhk.alertsystem.service;

import com.artwellhk.alertsystem.entity.AlertSnooze;

public interface SnoozeAccessorService {
	public static final String NAME = "SnoozeAccessor";
	public abstract AlertSnooze getSnooze(int sampleOrderId,int alertTypeId);
	
	
}
