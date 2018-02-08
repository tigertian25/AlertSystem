package com.artwellhk.alertsystem.entity;

import javax.persistence.Entity;
import javax.persistence.Table;
import java.util.UUID;
import javax.persistence.Column;
import com.haulmont.cuba.core.entity.BaseIntegerIdEntity;
import com.haulmont.cuba.core.entity.HasUuid;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import com.haulmont.chile.core.annotations.NamePattern;
import com.haulmont.chile.core.annotations.MetaProperty;
import javax.persistence.Transient;
import com.haulmont.cuba.core.entity.annotation.Listeners;

@Listeners("alertsystem_AlertTypeEntityListener")
@NamePattern("%s %s %s|fromProcess,toProcess,allowedDuration")
@Table(name = "ALERTSYSTEM_ALERT_TYPE")
@Entity(name = "alertsystem$AlertType")
public class AlertType extends BaseIntegerIdEntity {
    private static final long serialVersionUID = -5081258424674958866L;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "FROM_PROCESS_ID")
    protected Process fromProcess;

    @Transient
    @MetaProperty
    protected String fromProcessInfo;

    @Transient
    @MetaProperty
    protected String toProcessInfo;

    @Column(name = "FROM_PROCESS_TYPE", nullable = false)
    protected Integer fromProcessType;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "TO_PROCESS_ID")
    protected Process toProcess;

    @Column(name = "TO_PROCESS_TYPE", nullable = false)
    protected Integer toProcessType;

    @Column(name = "ALLOWED_DURATION")
    protected Integer allowedDuration;

    @Column(name = "SINGLE_MAX_DURATION")
    protected Integer singleMaxDuration;

    @Column(name = "TOTAL_MAX_DURATION")
    protected Integer totalMaxDuration;

    public void setFromProcessInfo(String fromProcessInfo) {
        this.fromProcessInfo = fromProcessInfo;
    }

    public String getFromProcessInfo() {
        return fromProcessInfo;
    }

    public void setToProcessInfo(String toProcessInfo) {
        this.toProcessInfo = toProcessInfo;
    }

    public String getToProcessInfo() {
        return toProcessInfo;
    }


    public ProcessType getToProcessType() {
        return toProcessType == null ? null : ProcessType.fromId(toProcessType);
    }

    public void setToProcessType(ProcessType toProcessType) {
        this.toProcessType = toProcessType == null ? null : toProcessType.getId();
    }


    public ProcessType getFromProcessType() {
        return fromProcessType == null ? null : ProcessType.fromId(fromProcessType);
    }

    public void setFromProcessType(ProcessType fromProcessType) {
        this.fromProcessType = fromProcessType == null ? null : fromProcessType.getId();
    }


    public void setFromProcess(Process fromProcess) {
        this.fromProcess = fromProcess;
    }

    public Process getFromProcess() {
        return fromProcess;
    }

    public void setToProcess(Process toProcess) {
        this.toProcess = toProcess;
    }

    public Process getToProcess() {
        return toProcess;
    }




    public void setAllowedDuration(Integer allowedDuration) {
        this.allowedDuration = allowedDuration;
    }

    public Integer getAllowedDuration() {
        return allowedDuration;
    }

    public void setSingleMaxDuration(Integer singleMaxDuration) {
        this.singleMaxDuration = singleMaxDuration;
    }

    public Integer getSingleMaxDuration() {
        return singleMaxDuration;
    }

    public void setTotalMaxDuration(Integer totalMaxDuration) {
        this.totalMaxDuration = totalMaxDuration;
    }

    public Integer getTotalMaxDuration() {
        return totalMaxDuration;
    }

    public AlertType(int id, Process fromProcess,Process toProcess,Integer allowedDuration,Integer fromProcessType,Integer toProcessType) {
    	this.id=id;this.allowedDuration=allowedDuration;
    	this.fromProcessType=fromProcessType;this.toProcessType=toProcessType;
    	this.fromProcess=fromProcess;this.toProcess=toProcess;
	}
    public AlertType(int id, Process fromProcess,Process toProcess,Integer allowedDuration,Integer fromProcessType,Integer toProcessType,Integer singleMaxDuration,Integer totalMaxDuration) {
    	this.id=id;this.allowedDuration=allowedDuration;
    	this.singleMaxDuration=singleMaxDuration;this.totalMaxDuration=totalMaxDuration;
    	this.fromProcessType=fromProcessType;this.toProcessType=toProcessType;
    	this.fromProcess=fromProcess;
    	this.toProcess=toProcess;
    }

	public AlertType() {
		// TODO Auto-generated constructor stub
	}

}