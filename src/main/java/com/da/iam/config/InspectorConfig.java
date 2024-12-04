package com.da.iam.config;

import com.da.iam.repo.impl.CustomInspector;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.util.Map;

@Configuration
@EnableJpaRepositories("com.**")
@EnableJpaAuditing(auditorAwareRef = "springSecurityAuditorAware")
@EnableTransactionManagement
public class JpaDatabaseAutoConfiguration implements HibernatePropertiesCustomizer {

    @Override
    public void customize(Map<String, Object> hibernateProperties) {
        hibernateProperties.put("hibernate.session_factory.statement_inspector", safeSqlInterceptor());
    }

    private SafeSqlInterceptor safeSqlInterceptor() {
        return new SafeSqlInterceptor();
    }
    //public class JpaDatabaseAutoConfiguration implements HibernatePropertiesCustomizer {
    //
    //    @Override
    //    public void customize(Map<String, Object> hibernateProperties) {
    //        hibernateProperties.put("hibernate.session_factory.statement_inspector", safeSqlInterceptor());
    //    }
    //
    //    private SafeSqlInterceptor safeSqlInterceptor() {
    //        return new SafeSqlInterceptor();
    //    }
    //}
}
