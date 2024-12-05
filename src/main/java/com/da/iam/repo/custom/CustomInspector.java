package com.da.iam.repo.custom;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.resource.jdbc.spi.StatementInspector;

@Slf4j
public class CustomInspector implements StatementInspector {
    @Override
    public String inspect(String sql) {
        if (sql != null && (sql.contains("1=1") && !sql.contains("0=0"))) {
            sql
                    .replace("lower", "unaccent(lower")
                    .replace(" like ", ") like unaccent(")
                    .replace("and 2=2", ")");
        }
        log.info("SQL: --------", sql);
        return sql;
    }
}
