package com.da.iam.repo.impl;

import org.hibernate.resource.jdbc.spi.StatementInspector;
import org.springframework.stereotype.Component;

@Component
public class CustomInspector implements StatementInspector {
    @Override
    public String inspect(String sql) {
//        if (sql != null) {
//            sql = sql.replace("u.email", "unaccent(u.email)")
//                    .replace("u.phone","unaccent(u.phone)")
//                    .replace("u.first_name", "unaccent(u.first_name)")
//                    .replace("u.last_name", "unaccent(u.last_name)")
//                    .replace("u.username", "unaccent(u.username)");
//        }
       return sql;
    }
}
