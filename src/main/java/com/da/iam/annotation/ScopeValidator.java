package com.da.iam.annotation;

import com.da.iam.entity.Scope;
import com.da.iam.service.PermissionService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;


public class ScopeValidator implements ConstraintValidator<ValidScope, Scope> {


    @Override
    public boolean isValid(Scope value, ConstraintValidatorContext context) {
        try {
            Scope.valueOf(value.name().toUpperCase()); // Check if the value is valid
            return true;
        } catch (IllegalArgumentException e) {
            return false; // Invalid scope value
        }
    }
}
