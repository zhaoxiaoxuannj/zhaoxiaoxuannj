package com.ais.security.threatanalysis.entity;

import java.io.Serializable;
import java.util.Set;

public class SingleDomainInfo implements Serializable {
    private String domain;
    private Long count;
    private String categoryName;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public Long getCount() {
        return count;
    }

    public void setCount(Long count) {
        this.count = count;
    }

    public String getCategoryName() {
        return categoryName;
    }

    public void setCategoryName(String categoryName) {
        this.categoryName = categoryName;
    }
}
