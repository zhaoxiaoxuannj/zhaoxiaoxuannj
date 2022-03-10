package com.ais.security.threatanalysis.entity;

import org.apache.kafka.common.serialization.Serializer;

import java.io.Serializable;
import java.util.Set;

public class AssetIpDomainInfo implements Serializable {
    private Long count;
    private Set<String> set;

    public AssetIpDomainInfo(Long count, Set<String> set){
        this.count = count;
        this.set = set;
    }
    public Set<String> getSet() {
        return set;
    }

    public void setSet(Set<String> set) {
        this.set = set;
    }

    public Long getCount() {
        return count;
    }

    public void setCount(Long count) {
        this.count = count;
    }

}
