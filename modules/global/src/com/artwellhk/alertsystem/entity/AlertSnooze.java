package com.artwellhk.alertsystem.entity;

import javax.persistence.Entity;
import javax.persistence.Table;
import com.haulmont.cuba.core.entity.BaseIntegerIdEntity;
import com.haulmont.cuba.core.entity.BaseUuidEntity;

import java.util.Date;
import javax.persistence.Column;
import com.haulmont.cuba.core.entity.Creatable;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import com.haulmont.chile.core.annotations.NamePattern;
import com.haulmont.cuba.core.entity.annotation.Listeners;

@Listeners("alertsystem_AlertSnoozeEntityListener")
@NamePattern("%s|duration")
@Table(name = "ALERTSYSTEM_ALERT_SNOOZE")
@Entity(name = "alertsystem$AlertSnooze")
public class AlertSnooze extends BaseUuidEntity implements Creatable {
    private static final long serialVersionUID = -7748561915348248329L;

    @Column(name = "SAMPLE_ORDER_ID", nullable = false)
    protected Integer sampleOrderId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ALERT_TYPE_ID")
    protected AlertType alertType;

    @Column(name = "DURATION")
    protected Integer duration;

    @Column(name = "CREATE_TS")
    protected Date createTs;

    @Column(name = "CREATED_BY", length = 50)
    protected String createdBy;



    public void setSampleOrderId(Integer sampleOrderId) {
        this.sampleOrderId = sampleOrderId;
    }

    public Integer getSampleOrderId() {
        return sampleOrderId;
    }


    public void setAlertType(AlertType alertType) {
        this.alertType = alertType;
    }

    public AlertType getAlertType() {
        return alertType;
    }


    public void setDuration(Integer duration) {
        this.duration = duration;
    }

    public Integer getDuration() {
        return duration;
    }

    public void setCreateTs(Date createTs) {
        this.createTs = createTs;
    }

    public Date getCreateTs() {
        return createTs;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getCreatedBy() {
        return createdBy;
    }


}