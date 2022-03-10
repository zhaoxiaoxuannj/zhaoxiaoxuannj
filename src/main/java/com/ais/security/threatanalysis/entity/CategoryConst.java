package com.ais.security.threatanalysis.entity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.ais.security.threatanalysis.mapper.TenantDomainCategoryMapper;

/**
 * @author chaoyan
 * @date 2021/6/17
 */
@Component
public class CategoryConst {

    @Autowired
    private TenantDomainCategoryMapper tenantDomainCategoryMapper;

    public static final Map<Integer, CategoryInfoEntity> DOMAIN_CATEGORY_INFO = new HashMap<>();

    public static final Map<Integer, CategoryGroupEntity> DOMAIN_CATEGORY_GROUP = new HashMap<>();

    public static final Set<Integer> DGA_OR_DNS_CODES = new HashSet<>();

    public static final Integer DGA_GROUP_ID = 14;
    public static final Integer DNS_GROUP_ID = 26;
    public static final Integer BLACKMAIL_GROUP_ID = 20;
    public static final Integer HEARTBEAT_GROUP_ID = 29;
    public static final Integer REBIND_GROUP_ID = 27;
    public static final Integer REFLECTION_GROUP_ID = 30;

    @PostConstruct
    public void init() {
        //DOMAIN_CATEGORY_INFO = new HashMap<>();
        //DOMAIN_CATEGORY_GROUP = new HashMap<>();
        //DGA_OR_DNS_CODES = new HashSet<>();
        List<Map<String, Object>> categories = tenantDomainCategoryMapper.getCategoryNameInfo(null);
        CategoryInfoEntity categoryInfo;
        CategoryGroupEntity groupInfo;
        for (Map<String, Object> category : categories) {
            int code = Integer.parseInt(category.get("category_code").toString());
            if (code == -1) {
                continue;
            }
            categoryInfo = new CategoryInfoEntity();
            categoryInfo.setCategoryCode(code);
            categoryInfo.setCategoryName(category.get("category_name").toString());
            categoryInfo.setGroupName(category.get("group_name").toString());
            categoryInfo.setGroupType(Integer.parseInt(category.get("group_type").toString()));
            categoryInfo.setGroupDetailType(Integer.parseInt(category.get("group_detail_type").toString()));
            categoryInfo.setGroupThreatLevel(Integer.parseInt(category.get("threat_level").toString()));
            int groupId = Integer.parseInt(category.get("group_id").toString());
            categoryInfo.setGroupId(groupId);
            DOMAIN_CATEGORY_INFO.put(code, categoryInfo);

            if (DOMAIN_CATEGORY_GROUP.get(groupId) == null) {
                groupInfo = new CategoryGroupEntity();
                groupInfo.setGroupId(groupId);
                groupInfo.setGroupName(category.get("group_name").toString());
                groupInfo.setGroupType(Integer.parseInt(category.get("group_type").toString()));
                groupInfo.setGroupDetailType(Integer.parseInt(category.get("group_detail_type").toString()));
                groupInfo.setGroupThreatLevel(Integer.parseInt(category.get("threat_level").toString()));
                DOMAIN_CATEGORY_GROUP.put(groupId, groupInfo);
            }

            if (groupId == 14 || groupId == 26 || groupId == 20 ) {
                DGA_OR_DNS_CODES.add(code);
            }
        }
    }

    public static Set<Integer> getDomainCodeByThreatLevel(Integer threatLevel) {
        Set<Integer> domainCodes = new HashSet<>();

        for (CategoryInfoEntity category : DOMAIN_CATEGORY_INFO.values()) {
            if (threatLevel == null || threatLevel.equals(category.getGroupThreatLevel())) {
                domainCodes.add(category.getCategoryCode());
            }
        }

        return domainCodes;
    }

    public static List<Integer> getThreatCategoryGroupId() {
        List<Integer> result = new ArrayList<>();

        for (CategoryGroupEntity groupInfo : CategoryConst.DOMAIN_CATEGORY_GROUP.values()) {
            if (groupInfo.getGroupType() == 1) {
                result.add(groupInfo.getGroupId());
            }
        }

        return result;
    }

    public static Map<Integer, Map<String, Object>> getCategoryDistributeInfo(Integer groupType, Integer contentDetailType) {
        Map<Integer, Map<String, Object>> categoryGroupInfo = new HashMap<>();
        Map<String, Object> groupInfo;
        for (CategoryGroupEntity group : CategoryConst.DOMAIN_CATEGORY_GROUP.values()) {
            if (group.getGroupType().equals(groupType) && (contentDetailType == null || contentDetailType.equals(group.getGroupDetailType()))) {
                groupInfo = new HashMap<>();
                groupInfo.put("value", 0);
                groupInfo.put("groupId", group.getGroupId());
                groupInfo.put("name", group.getGroupName());

                categoryGroupInfo.put(group.getGroupId(), groupInfo);
            }
        }

        return categoryGroupInfo;
    }

    public static Set<Integer> getDomainCodeByGroupId(int groupId) {
        Set<Integer> domainCodes = new HashSet<>();
        for (CategoryInfoEntity category: DOMAIN_CATEGORY_INFO.values()) {
            if (category.getGroupId() != null && groupId == category.getGroupId()) {
                domainCodes.add(category.getCategoryCode());
            }
        }
        return domainCodes;
    }

    public static Set<Integer> getDomainCodeByGroupIds(String[] groupIds) {
        Set<Integer> domainCodes = new HashSet<>();

        List<Integer> groups = new ArrayList<>();
        for (String groupId : groupIds) {
            groups.add(Integer.parseInt(groupId));
        }
        for (CategoryInfoEntity category: DOMAIN_CATEGORY_INFO.values()) {
            if (category.getGroupId() != null && groups.contains(category.getGroupId())) {
                domainCodes.add(category.getCategoryCode());
            }
        }
        return domainCodes;
    }

    public static List<CategoryGroupEntity> getGroupInfos(List<Integer> groupIds) {
        List<CategoryGroupEntity> groupInfos = new ArrayList<>();

        for (Integer groupId : groupIds) {
            if (DOMAIN_CATEGORY_GROUP.get(groupId) == null) {
                continue;
            }
            groupInfos.add(DOMAIN_CATEGORY_GROUP.get(groupId));
        }

        return groupInfos;
    }

    public static boolean containDgaOrDns(List<Integer> domainCode) {
        return !Collections.disjoint(domainCode, DGA_OR_DNS_CODES);
    }

}
