package com.artwellhk.alertsystem.entity;

import com.haulmont.chile.core.datatypes.impl.EnumClass;

import javax.annotation.Nullable;


public enum ReturnMsg implements EnumClass<String> {

    success("success"),
    error("error");

    private String id;

    ReturnMsg(String value) {
        this.id = value;
    }

    public String getId() {
        return id;
    }

    @Nullable
    public static ReturnMsg fromId(String id) {
        for (ReturnMsg at : ReturnMsg.values()) {
            if (at.getId().equals(id)) {
                return at;
            }
        }
        return null;
    }
}