package com.da.iam.repo.impl;

import com.da.iam.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserRepoCustom {
    List<User> searchByKeyword(String keyword, String sortBy,String sort, int currentSize, int currentPage);
}
