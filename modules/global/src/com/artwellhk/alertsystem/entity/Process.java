package com.artwellhk.alertsystem.entity;

import javax.persistence.Entity;
import javax.persistence.Table;
import com.haulmont.cuba.core.entity.BaseIntegerIdEntity;
import javax.persistence.Column;
import com.haulmont.chile.core.annotations.NamePattern;

@NamePattern("%s|name")
@Table(name = "ALERTSYSTEM_PROCESS")
@Entity(name = "alertsystem$Process")
public class Process extends BaseIntegerIdEntity {
	private static final long serialVersionUID = -8384761519220970052L;

	@Column(name = "NAME")
	protected String name;



    @Column(name = "DEPT_ID")
    protected Integer deptId;

    public void setDeptId(Integer deptId) {
        this.deptId = deptId;
    }

    public Integer getDeptId() {
        return deptId;
    }


	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
	public Process() {};
	public Process(int id,String name) {
		this.id=id;this.name=name;
	}

}