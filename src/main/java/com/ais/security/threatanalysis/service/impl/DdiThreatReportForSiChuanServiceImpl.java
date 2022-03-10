package com.ais.security.threatanalysis.service.impl;

import com.ais.security.threatanalysis.entity.AssetIpDomainInfo;
import com.ais.security.threatanalysis.entity.CategoryConst;
import com.ais.security.threatanalysis.entity.CategoryGroupEntity;
import com.ais.security.threatanalysis.entity.DdiThreatReportParams;
import com.ais.security.threatanalysis.entity.GlobalAddressLibrary;
import com.ais.security.threatanalysis.entity.SingleDomainInfo;
import com.ais.security.threatanalysis.entity.TenantConst;
import com.ais.security.threatanalysis.entity.WapiResponse;
import com.ais.security.threatanalysis.mapper.IpLocationInfoMapper;
import com.ais.security.threatanalysis.util.IPUtil;
import com.ais.security.threatanalysis.vo.ThreatAssetDomainVo;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.script.Script;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.bucket.nested.Nested;
import org.elasticsearch.search.aggregations.bucket.terms.IncludeExclude;
import org.elasticsearch.search.aggregations.bucket.terms.Terms;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.elasticsearch.search.aggregations.metrics.Cardinality;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;


/**
 * @author chaoyan
 * @date 2021/6/4
 */
@Service
public class DdiThreatReportForSiChuanServiceImpl  {
    final Logger log = LogManager.getLogger(DdiThreatReportForSiChuanServiceImpl.class);
    private static final DateTimeFormatter DAY_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    ThreadFactory threatReportSubscriptionNamedThreadFactory = new ThreadFactoryBuilder()
            .setNameFormat("tenant-threat-create-report-thread-%d").build();
    ExecutorService threatReportSubscriptionPool = new ThreadPoolExecutor(10, 20, 100L,TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(100), threatReportSubscriptionNamedThreadFactory, new ThreadPoolExecutor.CallerRunsPolicy());

    @Autowired
    private ElasticSearchOperateServiceImpl elasticSearchOperateService;

    @Resource
    private IpLocationInfoMapper ipLocationInfoMapper;


    public static final List<GlobalAddressLibrary> addressLibraries = new ArrayList<>();

    @Value("${threat.assetip.filepath:/home/aisddi/data/}")
    private String assetipFilePath;
    @PostConstruct
    public void init() {
        addressLibraries.addAll(ipLocationInfoMapper.getAllOrderByStartIpAsc());
    }

    private String getExistQueryIndex(boolean isDomain, int statPeriod, String tenantId) {
        String queryIndex;
        if (isDomain) {
            queryIndex = "ddi-request-domain-" + tenantId;
        } else {
            queryIndex = "ddi-request-ip-" + tenantId;
        }
        if (statPeriod == TenantConst.StatPeriod.LATEST_7_DAYS) {
            queryIndex = queryIndex + "-7days";
        } else if (statPeriod == TenantConst.StatPeriod.LATEST_30_DAYS) {
            queryIndex = queryIndex + "-30days";
        } else if (statPeriod == TenantConst.StatPeriod.LATEST_90_DAYS) {
            queryIndex = queryIndex + "-90days";
        } else {
            log.info("getExistQueryIndex 方法中 statPeriod 非 2/3/4");
        }

        if (!elasticSearchOperateService.indexExist(queryIndex)) {
            log.info("要查询的索引[{}]不存在", queryIndex);
            return null;
        }
        return queryIndex;
    }

    /**
     * 有用
     * @param params
     * @return
     */
    public WapiResponse getDdiTopLostAsset(DdiThreatReportParams params) {
        Map<String, Object> result;
        try {
            if (params.getStatPeriod() == TenantConst.StatPeriod.TODAY) {
                result = getDdiLostAssetToday(params.getTenantId());
            } else {
                result = getDdiLostAssetOther(params);
            }
        } catch (IOException e) {
            log.error("查询失陷资产失败，原因：{}", e.getMessage());
            result = new HashMap<>();
        }

        WapiResponse response = new WapiResponse();
        response.setResult(result);
        return response;
    }

    /**
     * 四川环境提数据要求
     * @param buckets,affectedAssets的buckets
     * @return
     */
    private List<ThreatAssetDomainVo> parseThreatLostAsset(List<? extends Terms.Bucket> buckets) {
        List<ThreatAssetDomainVo> allThreatAssets = new ArrayList<>();
        ThreatAssetDomainVo assetInfo;
        for (Terms.Bucket bucket : buckets) {
            Map<String, AssetIpDomainInfo> parsedRes = getThreatLevelAndCategoryName(null, ((Terms) bucket.getAggregations().get("domainCodes")).getBuckets());
             parsedRes.putAll(getThreatLevelAndCategoryName(null, ((Terms) bucket.getAggregations().get("primarydomainCodes")).getBuckets()));

            assetInfo = new ThreatAssetDomainVo();
            Iterator<Map.Entry<String,AssetIpDomainInfo>> iterator = parsedRes.entrySet().iterator();
            Long requestCount = 0L;
            assetInfo.setAssetIp(bucket.getKeyAsString());
            GlobalAddressLibrary addressLibrary = IPUtil.IpBinarySearch(bucket.getKeyAsString(), addressLibraries);
            if (addressLibrary == null) {
                assetInfo.setBelong("未知");
            } else {
                assetInfo.setBelong(addressLibrary.getLocation());
            }
            while (iterator.hasNext())
            {
                Map.Entry<String,AssetIpDomainInfo> entry = iterator.next();
                AssetIpDomainInfo assetIpDomainInfo= entry.getValue();
                String categoryNames = String.join(",",assetIpDomainInfo.getSet());
                Long singleCount = assetIpDomainInfo.getCount();
                requestCount = requestCount + singleCount;
                String domain = entry.getKey();
                SingleDomainInfo singleDomainInfo = new SingleDomainInfo();
                singleDomainInfo.setDomain(domain);
                singleDomainInfo.setCategoryName(categoryNames);
                singleDomainInfo.setCount(singleCount);
                assetInfo.getSingleDomainInfos().add(singleDomainInfo);
            }
            assetInfo.setCount(requestCount);
            allThreatAssets.add(assetInfo);
        }

        return allThreatAssets;
    }

    /**
     * ddi-request-ip-{tenantid}表的分析
     * @param buckets
     * @param queryCategoryGroupIds
     * @return
     */
    private List<ThreatAssetDomainVo> parseThreatLostAssetOther(List<? extends Terms.Bucket> buckets, List<String> queryCategoryGroupIds) {
        List<ThreatAssetDomainVo> allThreatAssets = new ArrayList<>();
        ThreatAssetDomainVo assetInfo;
        for (Terms.Bucket bucket : buckets) {
            Map<String, AssetIpDomainInfo> parsedRes = getThreatLevelAndCategoryName(null, ((Terms) ((Nested) bucket.getAggregations().get("domaincodedomainparent")).getAggregations().asMap().get("domaincodedomain")).getBuckets());
            assetInfo = new ThreatAssetDomainVo();
            Iterator<Map.Entry<String,AssetIpDomainInfo>> iterator = parsedRes.entrySet().iterator();
            Long requestCount = 0L;
            assetInfo.setAssetIp(bucket.getKeyAsString());
            GlobalAddressLibrary addressLibrary = IPUtil.IpBinarySearch(bucket.getKeyAsString(), addressLibraries);
            if (addressLibrary == null) {
                assetInfo.setBelong("未知");
            } else {
                assetInfo.setBelong(addressLibrary.getLocation());
            }
            while (iterator.hasNext())
            {
                Map.Entry<String,AssetIpDomainInfo> entry = iterator.next();
                AssetIpDomainInfo assetIpDomainInfo= entry.getValue();
                String categoryNames = String.join(",",assetIpDomainInfo.getSet());
                Long singleCount = assetIpDomainInfo.getCount();
                requestCount = requestCount + singleCount;
                String domain = entry.getKey();
                SingleDomainInfo singleDomainInfo = new SingleDomainInfo();
                singleDomainInfo.setDomain(domain);
                singleDomainInfo.setCategoryName(categoryNames);
                singleDomainInfo.setCount(singleCount);
                assetInfo.getSingleDomainInfos().add(singleDomainInfo);
            }
            assetInfo.setCount(requestCount);
            allThreatAssets.add(assetInfo);
        }

        return allThreatAssets;
    }
    private Map<String, AssetIpDomainInfo> getThreatLevelAndCategoryName(Integer excludeGroup, List<? extends Terms.Bucket> buckets) {
        Integer maxThreatLevel = 0;
        Set<CategoryGroupEntity> groups = new HashSet<>();
        Map<String, AssetIpDomainInfo> domainResult = new HashMap<>();
        for (Terms.Bucket bucket : buckets) {
            String[] dCodeAndmain = bucket.getKeyAsString().split("\\|");
            int domainCode = Integer.valueOf(dCodeAndmain[0]).intValue();
            long count = bucket.getDocCount();
            String domain = dCodeAndmain[1];
            if (CategoryConst.DOMAIN_CATEGORY_INFO.get(domainCode) == null) {
                continue;
            }
            if(!domainResult.keySet().contains(domain))
            {
                Set<String> set = new HashSet<>();
                set.add(CategoryConst.DOMAIN_CATEGORY_GROUP.get(CategoryConst.DOMAIN_CATEGORY_INFO.get(domainCode).getGroupId()).getGroupName());
                AssetIpDomainInfo assetIpDomainInfo = new AssetIpDomainInfo(count,set);
                domainResult.put(domain,assetIpDomainInfo);
//                domainResult.put(domain,set.add(domainCode+"|"+CategoryConst.DOMAIN_CATEGORY_GROUP.get(CategoryConst.DOMAIN_CATEGORY_INFO.get(domainCode).getGroupId())));
            }
            else{
                AssetIpDomainInfo assetIpDomainInfo = domainResult.get(domain);
                assetIpDomainInfo.setCount(assetIpDomainInfo.getCount()+count);
                assetIpDomainInfo.getSet().add(CategoryConst.DOMAIN_CATEGORY_GROUP.get(CategoryConst.DOMAIN_CATEGORY_INFO.get(domainCode).getGroupId()).getGroupName());
                domainResult.put(domain,assetIpDomainInfo);
            }
        }
//        Map<String, Object> result = new HashMap<>();
//        result.put("threatLevel", maxThreatLevel);
//        result.put("threatGroups", groups.stream().sorted((a, b) -> b.getGroupThreatLevel() - a.getGroupThreatLevel()).collect(Collectors.toList()));
//        result.put("threatGroupIds", groups.stream().map(a -> a.getGroupId().toString()).collect(Collectors.toList()));
        return domainResult;
    }

    /**
     * 有用
     * @param tenantId
     * @return
     * @throws IOException
     */
    private Map<String, Object> getDdiLostAssetToday(String tenantId) throws IOException {
        Map<String, Object> result = new HashMap<>();
        String queryIndex = TenantConst.EsIndex.DDI_THREAT_ORIGINAL_INDEX_PREFIX + tenantId + "-" + DAY_FORMATTER.format(LocalDate.now());
        if (!elasticSearchOperateService.indexExist(queryIndex)) {
            return getWapiResponsePageResult();
        }
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        TermsAggregationBuilder termsAgg = AggregationBuilders.terms("affectedAssets").field("private_ip").size(Integer.MAX_VALUE)
                .subAggregation(AggregationBuilders.terms("primarydomainCodes").script(new Script("doc['domain_code'].value+'|'+doc['primary_domain'].value")).includeExclude(new IncludeExclude("11317.*|11308.*",null)))
                .subAggregation(AggregationBuilders.terms("domainCodes").script(new Script("doc['domain_code'].value+'|'+doc['domain'].value")).includeExclude(new IncludeExclude(null,"11317.*|11308.*")))
                ;
        SearchResponse searchResponse = elasticSearchOperateService.getSearchResponse(queryBuilder, termsAgg, queryIndex);
        List<? extends Terms.Bucket> buckets = ((Terms) searchResponse.getAggregations().get("affectedAssets")).getBuckets();
        // 解析聚合结果
        List<ThreatAssetDomainVo> allThreatAssets = parseThreatLostAsset(buckets);
        threatReportSubscriptionPool.execute(()->{
            ouputToFile(allThreatAssets);
        });
        result.put("data", allThreatAssets);
        result.put("total", allThreatAssets.size());
        return result;
    }


    private Map<String, Object> getDdiLostAssetOther(DdiThreatReportParams params) throws IOException {
        Map<String, Object> result = new HashMap<>();
        String queryIndex = getExistQueryIndex(false, params.getStatPeriod(), params.getTenantId());

        if (queryIndex == null) {
            return getWapiResponsePageResult();
        }

        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery().filter(QueryBuilders.termsQuery("threat_level", Arrays.asList(1, 2, 3)));
        if (params.getStatPeriod() == TenantConst.StatPeriod.YESTERDAY) {
            queryBuilder.filter(QueryBuilders.termQuery(TenantConst.IndexField.RECORD_DATE, DAY_FORMATTER.format(LocalDate.now().minusDays(1))));
        }
        LinkedHashMap<String, Boolean> orders = new LinkedHashMap<>();
        orders.put("threat_level", true);
        orders.put("total_request", true);
        TermsAggregationBuilder termsAgg = AggregationBuilders.terms("affectedAssets").field("asset_ip").size(Integer.MAX_VALUE)
                .subAggregation(AggregationBuilders.nested("domaincodedomainparent","threat_domain")
                        .subAggregation(AggregationBuilders.terms("domaincodedomain").script(new Script("doc['threat_domain.domain_code'].value+'|'+doc['threat_domain.domain'].value"))))
                ;
        SearchResponse searchResponse = elasticSearchOperateService.getSearchResponse(queryBuilder, termsAgg, queryIndex);
        List<String> queryCategoryGroupIds = new ArrayList<>();
        List<? extends Terms.Bucket> buckets = ((Terms) searchResponse.getAggregations().get("affectedAssets")).getBuckets();
        // 解析聚合结果
        List<ThreatAssetDomainVo> allThreatAssets = parseThreatLostAssetOther(buckets, queryCategoryGroupIds);
        threatReportSubscriptionPool.execute(()->{
            ouputToFile(allThreatAssets);
        });
        result.put("data", allThreatAssets);
        result.put("total", allThreatAssets.size());

        return result;
    }

    private Map<String, Object> getWapiResponsePageResult() {
        Map<String, Object> result = new HashMap<>();
        result.put("total", 0);
        result.put("data", new ArrayList<>());

        return result;
    }
    private void ouputToFile(List<ThreatAssetDomainVo> threatAssetDomainVos)
    {
        String filename =  LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS"));
        String osname = System.getProperty("os.name");
        String filePath="C:\\Users\\Zxx\\Downloads\\"+filename+".csv";
        if(!osname.toLowerCase().startsWith("window"))
        {
            filePath = assetipFilePath+filename+".csv";
        }
        try(BufferedOutputStream bufferedWriter = new BufferedOutputStream(new FileOutputStream(new File(filePath),true))){
            bufferedWriter.write("失陷主机,归属地,总请求次数,域名|威胁类型|该域名总请求次数\r\n".getBytes(StandardCharsets.UTF_8));
            bufferedWriter.flush();
           threatAssetDomainVos.stream().forEach(a->{
               List<SingleDomainInfo> singleDomainInfos=a.getSingleDomainInfos();
               StringBuilder domainStr = new StringBuilder();
               singleDomainInfos.stream().forEach(b->{domainStr.append(b.getDomain()+"|"+b.getCategoryName()+"|"+b.getCount()+",");});
               try {
                   bufferedWriter.write((a.getAssetIp() + "," + a.getBelong() + "," + a.getCount() + "," + domainStr.toString().substring(0,domainStr.length()-1)+"\r\n").getBytes(StandardCharsets.UTF_8));
                   bufferedWriter.flush();
               }catch (Exception e){
                   log.error(e.getMessage());
               }
           });
        }
        catch (Exception e)
        {
            log.error(e.getMessage());
        }
    }
}
