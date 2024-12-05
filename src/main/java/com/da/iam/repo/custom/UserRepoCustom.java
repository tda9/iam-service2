package com.da.iam.repo.custom;

import com.da.iam.entity.User;

import java.util.List;

public interface UserRepoCustom {
    List<User> searchByKeyword(String keyword, String sortBy,String sort, int currentSize, int currentPage);
}
