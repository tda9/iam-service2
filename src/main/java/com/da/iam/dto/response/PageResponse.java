package com.da.iam.dto.response;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;
@Getter
@Setter
public class PageResponse<T> extends BasedResponse<List<T>> {
    int currentPage;
    int totalPage;
    int currentSize;
    long totalSize;
    String sortBy;
    String sort;

    public PageResponse(int currentPage,
                        int totalPage,
                        int currentSize,
                        long totalSize,
                        String sortBy,
                        String sort,
                        List<T> data){
        super.setData(data);
        this.currentPage = currentPage;
        this.totalPage = totalPage;
        this.currentSize = currentSize;
        this.totalSize = totalSize;
        this.sortBy = sortBy;
        this.sort = sort;
    }
}
