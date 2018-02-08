package com.artwellhk.alertsystem.entity;

import com.haulmont.chile.core.datatypes.impl.EnumClass;

import javax.annotation.Nullable;


public enum AlertTypeID implements EnumClass<Integer> {

    GongYiNoReceive(102),
    HuaHuaNoSend(103),
    HuaHuaNoReceive(104),
    DianJiNoSend(105),
    DianJiNoReceive(106),
    TaoKouNoSend(107),
    TaoKouNoReceive(108),
    ShouFengNoSend(109),
    ShouFengNoReceive(110),
    XiShuiNoSend(111),
    XiShuiNoReceive(112),
    TangYiNoSend(113),
    TangYiNoReceive(114);

    private Integer id;

    AlertTypeID(Integer value) {
        this.id = value;
    }

    public Integer getId() {
        return id;
    }

    @Nullable
    public static AlertTypeID fromId(Integer id) {
        for (AlertTypeID at : AlertTypeID.values()) {
            if (at.getId().equals(id)) {
                return at;
            }
        }
        return null;
    }
}