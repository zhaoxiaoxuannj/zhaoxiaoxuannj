package com.ais.security.threatanalysis.entity;

/**
 * @author chaoyan
 * @date 2020/11/15
 */
public interface TenantConst {

    final class StatPeriod {
        public static final int TODAY = 0;
        public static final int YESTERDAY = 1;
        public static final int LATEST_7_DAYS = 2;
        public static final int LATEST_30_DAYS = 3;
        public static final int LATEST_90_DAYS = 4;
    }

    final class EsIndex {
        // ddi威胁日志原始索引
        public static final String DDI_THREAT_ORIGINAL_INDEX_PREFIX = "ddi-threat-request-";
        // ddi内容日志原始索引
        public static final String DDI_CONTENT_ORIGINAL_INDEX_PREFIX = "ddi-content-request-";
        // ddi 不良&违法日志原始索引
        public static final String DDI_BAD_ORIGINAL_INDEX_PREFIX = "ddi-bad-request-";
        // 存放ddi天聚合数据的索引（按照域名维度）
        public static final String DDI_DAY_DOMAIN_INDEX_PREFIX = "ddi-request-domain-";
        // 存档ddi天聚合数据的索引（按照资产维度）
        public static final String DDI_DAY_IP_INDEX_PREFIX = "ddi-request-ip-";
    }

    final class LogStatisticsBlockType {
        // 威胁
        public static final int THREAT = 1;
        // 内容
        public static final int CONTENT = 0;
        // 黑名单
        public static final int BLACK_LIST = -1;
    }

    final class TENANT_INVITATION_CODE_INFO_STATUS {
        // 正常
        public static final String STATUS_NORMAL = "0";
        // 失效
        public static final String STATUS_EXPIRED = "1";
    }

    final class ReportType {
        // 租户拦截统计报表
        public static final int TENANT_INTERCEPT_REPORT = 0;
        // DDI威胁分析报表
        public static final int DDI_THREAT_REPORT = 1;
    }

    final class ThreatLevel {
        // 高危
        public static final int HIGH = 3;
        // 中危
        public static final int MEDIUM = 2;
        // 低危
        public static final int LOW = 1;
    }

    final class InterceptIndex {
        public static final String INTERCEPT_HOUR_INDEX_PREFIX = "tenant-intercept-hour-";
        public static final String INTERCEPT_DAY_INDEX_PREFIX = "tenant-intercept-day-";
    }


    final class Permission {
        public static final String ROLE_CACHE_PREFIX = "ROLE_CACHE#";
        public static final String TOKEN_KEY = "auth_token";
        public static final String MENU_CACHE_PREFIX = "MENU_CACHE#";
    }

    final class User {
        public static final String USER_CACHE_PREFIX = "USER_CACHE#";
        public static final String USER_SPLIT = "/";

    }

    final class DOMAIN_CATEGORY_GROUP {
        /**
         * 违法
         */
        public static final int ILLEGAL = 2;
        /**
         * 不良
         */
        public static final int BAD = 7;
    }

    final class ReportPeriod {
        public static final int REAL_REPORT = 0;
        public static final int DAY_REPORT = 1;
        public static final int WEEK_REPORT = 2;
        public static final int MONTH_REPORT = 3;
    }

    final class IndexField {
        // 聚合后的资产IP字段名
        public static final String ASSET_IP = "asset_ip";
        // 原始记录中的资产IP（私网IP）
        public static final String PRIVATE_IP = "private_ip";
        // 按照文档数排序字段
        public static final String DOC_COUNT_SORT = "_count";
        // 威胁等级
        public static final String THREAT_LEVEL = "threat_level";
        // 域名
        public static final String DOMAIN = "domain";
        // 域名解析IP
        public static final String DOMAIN_IPS = "domain_ips";
        // 域名类型
        public static final String DOMAIN_TYPE = "domain_type";
        // 域名来源
        public static final String DOMAIN_SOURCE = "domain_source";
        // 请求时间
        public static final String REQUEST_TIME = "request_time";
        // 原始记录索引中的字段主域名（分类为DGA和DNS隧道时，该字段有值，其他分类，该字段为空）
        public static final String PRIMARY_DOMAIN = "primary_domain";
        // 域名分类code（小类，对应DOMAIN_CATEGORY_INFO表中的category_code字段）
        public static final String DOMAIN_CODE = "domain_code";
        // 域名分组大类 -- 统计后的字段
        public static final String CATEGORY_GROUP_ID = "category_group_id";
        // 数据统计日期 -- 统计后的字段
        public static final String RECORD_DATE = "record_date";
        // 总请求量 -- 统计后的字段
        public static final String TOTAL_REQUEST = "total_request";
        // 域名请求信息 -- 统计后的字段
        public static final String REQUEST_INFO = "request_info";
        // 首次请求时间 -- 统计后的字段
        public static final String FIRST_REQUEST_TIME = "first_request_time";
        // 最后一次请求时间 -- 统计后的字段
        public static final String LATEST_REQUEST_TIME = "latest_request_time";
        // 资产访问的威胁域名
        public static final String THREAT_DOMAIN = "threat_domain";
        // 资产访问的威胁分组大类
        public static final String THREAT_CATEGORY_GROUP= "threat_category_group";
    }

    final class IndexDisplayField {
        // 威胁等级
        public static final String THREAT_LEVEL = "threatLevel";
        // 域名
        public static final String DOMAIN = "domain";
        // 请求量
        public static final String REQUEST = "request";
    }

    /**
     * 威胁告警查询周期
     */
    final class ThreatAlarmPeriodConstants{
        // 今天
        public static final int TODAY = 1;
        // 本周
        public static final int THIS_WEEK = 2;
        // 本月
        public static final int THIS_MONTH = 3;
        // 自定义
        public static final int CUSTOM_TIME = 4;

    }
}
