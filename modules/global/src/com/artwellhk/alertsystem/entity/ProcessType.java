package com.artwellhk.alertsystem.entity;

import com.haulmont.chile.core.datatypes.impl.EnumClass;

import javax.annotation.Nullable;


public enum ProcessType implements EnumClass<Integer> {

    send(1),
    receive(2);

    private Integer id;

    ProcessType(Integer value) {
        this.id = value;
    }

    public Integer getId() {
        return id;
    }

    @Nullable
    public static ProcessType fromId(Integer id) {
        for (ProcessType at : ProcessType.values()) {
            if (at.getId().equals(id)) {
                return at;
            }
        }
        return null;
    }
}