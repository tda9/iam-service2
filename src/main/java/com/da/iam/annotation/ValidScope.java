package com.da.iam.annotation;


import jakarta.validation.Constraint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = ScopeValidator.class)
public @interface ValidScope {

    String message() default "Invalid scope provided";
    Class<?>[] groups()default {};
    Class<?>[] payload() default {};
}
