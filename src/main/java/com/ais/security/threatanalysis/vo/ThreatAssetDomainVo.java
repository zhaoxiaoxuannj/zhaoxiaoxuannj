package com.ais.security.threatanalysis.vo;


import com.ais.security.threatanalysis.entity.CategoryGroupEntity;
import com.ais.security.threatanalysis.entity.SingleDomainInfo;

import java.util.LinkedList;
import java.util.List;

/**
 * @author chaoyan
 * @date 2021/6/17
 */
public class ThreatAssetDomainVo  {
    private String assetIp;
    private List<SingleDomainInfo> singleDomainInfos =new LinkedList<>();
    private Long count;
    private String belong;

    public String getAssetIp() {
        return assetIp;
    }

    public void setAssetIp(String assetIp) {
        this.assetIp = assetIp;
    }

    public List<SingleDomainInfo> getSingleDomainInfos() {
        return singleDomainInfos;
    }

    public Long getCount() {
        return count;
    }

    public void setCount(Long count) {
        this.count = count;
    }

    public String getBelong() {
        return belong;
    }

    public void setBelong(String belong) {
        this.belong = belong;
    }
}

