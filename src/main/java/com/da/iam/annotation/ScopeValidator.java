package com.da.iam.annotation;

import com.da.iam.service.PermissionService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ScopeValidator implements ConstraintValidator<ValidScope, String> {
    private final PermissionService permissionService;

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if(value == null || value.isEmpty()) return false;
        return permissionService.getScopes().contains(value);
    }
}
