package com.ais.security.threatanalysis.entity;

/**
 * @author chaoyan
 * @date 2021/6/10
 */
public class DdiThreatReportParams {
    // 统计周期，0：今天；1：昨天；2：近7天；3：近30天；4：近90天
    private Integer statPeriod;

    private String tenantId;

    // 域名类型，1：威胁；0：内容；
    private Integer domainType;

    // 域名分组ID
    private Integer categoryGroupId;

    // 域名分组集合，逗号分隔
    private String categoryGroupIds;

    // 威胁等级
    private Integer threatLevel;

    // 域名
    private String domain;

    // 资产IP
    private String privateIp;

    private Integer pageSize = 10;

    private Integer pageNum = 1;
    private String alarmTime;

    public Integer getStatPeriod() {
        return statPeriod;
    }

    public void setStatPeriod(Integer statPeriod) {
        this.statPeriod = statPeriod;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public Integer getDomainType() {
        return domainType;
    }

    public void setDomainType(Integer domainType) {
        this.domainType = domainType;
    }

    public Integer getCategoryGroupId() {
        return categoryGroupId;
    }

    public void setCategoryGroupId(Integer categoryGroupId) {
        this.categoryGroupId = categoryGroupId;
    }

    public String getCategoryGroupIds() {
        return categoryGroupIds;
    }

    public void setCategoryGroupIds(String categoryGroupIds) {
        this.categoryGroupIds = categoryGroupIds;
    }

    public Integer getThreatLevel() {
        return threatLevel;
    }

    public void setThreatLevel(Integer threatLevel) {
        this.threatLevel = threatLevel;
    }

    public Integer getPageSize() {
        return pageSize;
    }

    public void setPageSize(Integer pageSize) {
        this.pageSize = pageSize;
    }

    public Integer getPageNum() {
        return pageNum;
    }

    public void setPageNum(Integer pageNum) {
        this.pageNum = pageNum;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPrivateIp() {
        return privateIp;
    }

    public void setPrivateIp(String privateIp) {
        this.privateIp = privateIp;
    }

    public String getAlarmTime() {
        return alarmTime;
    }

    public void setAlarmTime(String alarmTime) {
        this.alarmTime = alarmTime;
    }
}
