package com.artwellhk.alertsystem.entity;

import com.haulmont.chile.core.datatypes.impl.EnumClass;

import javax.annotation.Nullable;


public enum ProcessIdEnum implements EnumClass<Integer> {

    GongYi(2),
    HuaHua(3);

    private Integer id;

    ProcessIdEnum(Integer value) {
        this.id = value;
    }

    public Integer getId() {
        return id;
    }

    @Nullable
    public static ProcessIdEnum fromId(Integer id) {
        for (ProcessIdEnum at : ProcessIdEnum.values()) {
            if (at.getId().equals(id)) {
                return at;
            }
        }
        return null;
    }
}