package com.ais.security.threatanalysis.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;
import java.util.Map;

/**
 * @author  xphu
 * @date  2021/3/11 17:00
 * @describe 租户策略-资产组关联关系表持久层类
 **/
@Mapper
public interface TenantDomainCategoryMapper {


    @Select(
            "<script>" +
                    " select category_code, i.group_id, category_name, group_name, group_type, threat_level, group_detail_type" +
                    " from DOMAIN_CATEGORY_INFO i, DOMAIN_CATEGORY_GROUP g " +
                    " where i.group_id = g.group_id " +
                    "   <if test=\"category_codes != null and category_codes != ''\">" +
                    "     and category_code in (${category_codes})" +
                    "   </if>" +
            "</script>"
    )
    List<Map<String, Object>> getCategoryNameInfo(@Param("category_codes") String categoryCodes);


    /**
     * 查询分组类别信息
     * @param
     * @return
     */
    @Select("<script>" +
            " select group_id as groupId,group_name as groupName,group_des as groupDes ,threat_level as threatLevel" +
            " from DOMAIN_CATEGORY_GROUP g\n" +
            " where 1=1\n" +
            "   <if test=\"groupType!=null\">\n" +
            "       and g.group_type = #{groupType}\n" +
            "   </if>\n" +
            "   <if test=\"groupIds!=null and groupIds.size()>0\">\n" +
            "       and g.group_id in\n" +
            "       <foreach collection=\"groupIds\" item=\"item\" index=\"index\" open=\"(\" separator=\",\" close=\")\">\n" +
            "            #{item}\n" +
            "       </foreach>\n" +
            "   </if>\n" +
            "   <if test=\"groupDetailType!=null\">\n" +
            "       and g.group_detail_type = #{groupDetailType}\n" +
            "   </if>\n" +
            "   <if test=\"threatLevel!=null\">\n" +
            "       and g.threat_level = #{threatLevel}\n" +
            "   </if>\n" +
            " order by sort, groupId" +
            "</script>"
    )
    List<Map<String, Object>> findCategoryGroup(Map<String, Object> param);
}
