package com.da.iam.entity;

import lombok.Getter;

@Getter
public enum Scope {
    READ,
            //("read_permission"),
    CREATE,
    //("write_permission"),
    DELETE,
    //("delete_permission"),
    UPDATE
    //("admin_permission");

//    private final String description;
//
//    Scope(String description) {
//        this.description = description;
//    }
//
//    @Override
//    public String toString() {
//        return description;
//    }
}
