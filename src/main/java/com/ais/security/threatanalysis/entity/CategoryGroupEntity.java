package com.ais.security.threatanalysis.entity;

/**
 * @author chaoyan
 * @date 2021/6/10
 */
public class CategoryGroupEntity implements Comparable<CategoryGroupEntity> {

    private Integer groupId;
    private String groupName;
    private Integer groupType;
    private Integer groupThreatLevel;
    private Integer groupDetailType;

    public Integer getGroupId() {
        return groupId;
    }

    public void setGroupId(Integer groupId) {
        this.groupId = groupId;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public Integer getGroupType() {
        return groupType;
    }

    public void setGroupType(Integer groupType) {
        this.groupType = groupType;
    }

    public Integer getGroupThreatLevel() {
        return groupThreatLevel;
    }

    public void setGroupThreatLevel(Integer groupThreatLevel) {
        this.groupThreatLevel = groupThreatLevel;
    }

    public Integer getGroupDetailType() {
        return groupDetailType;
    }

    public void setGroupDetailType(Integer groupDetailType) {
        this.groupDetailType = groupDetailType;
    }

    @Override
    public int compareTo(CategoryGroupEntity o) {
        return o.getGroupThreatLevel() - this.groupThreatLevel;
    }
}
