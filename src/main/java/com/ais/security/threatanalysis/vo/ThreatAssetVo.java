package com.ais.security.threatanalysis.vo;


import com.ais.security.threatanalysis.entity.CategoryGroupEntity;

import java.util.List;

/**
 * @author chaoyan
 * @date 2021/6/17
 */
public class ThreatAssetVo implements Comparable<ThreatAssetVo> {

    private Integer sort;

    private String assetIp;

    private Integer threatLevel = -1;

    private List<CategoryGroupEntity> threatGroups;

    private Integer threatDomainNum;

    private Integer totalRequest = 0;

    private String latestRequestTime;

    private List<String> threatGroupNames;

    public Integer getSort() {
        return sort;
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getAssetIp() {
        return assetIp;
    }

    public void setAssetIp(String assetIp) {
        this.assetIp = assetIp;
    }

    public Integer getThreatLevel() {
        return threatLevel;
    }

    public void setThreatLevel(Integer threatLevel) {
        this.threatLevel = threatLevel;
    }

    public List<CategoryGroupEntity> getThreatGroups() {
        return threatGroups;
    }

    public void setThreatGroups(List<CategoryGroupEntity> threatGroups) {
        this.threatGroups = threatGroups;
    }

    public Integer getThreatDomainNum() {
        return threatDomainNum;
    }

    public void setThreatDomainNum(Integer threatDomainNum) {
        this.threatDomainNum = threatDomainNum;
    }

    public Integer getTotalRequest() {
        return totalRequest;
    }

    public void setTotalRequest(Integer totalRequest) {
        this.totalRequest = totalRequest;
    }

    public String getLatestRequestTime() {
        return latestRequestTime;
    }

    public void setLatestRequestTime(String latestRequestTime) {
        this.latestRequestTime = latestRequestTime;
    }

    public List<String> getThreatGroupNames() {
        return threatGroupNames;
    }

    public void setThreatGroupNames(List<String> threatGroupNames) {
        this.threatGroupNames = threatGroupNames;
    }

    @Override
    public int compareTo(ThreatAssetVo threatAsset) {
        int first = this.getThreatLevel() - threatAsset.getThreatLevel();
        if (first == 0) {
            if (this.totalRequest - threatAsset.getTotalRequest() == 0 &&
                    this.latestRequestTime != null) {
                return -this.latestRequestTime.compareTo(threatAsset.latestRequestTime);
            }
            return -(this.totalRequest - threatAsset.getTotalRequest());
        }
        return -first;
    }
}

