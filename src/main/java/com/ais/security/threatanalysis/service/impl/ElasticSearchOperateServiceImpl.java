package com.ais.security.threatanalysis.service.impl;

import com.ais.security.threatanalysis.entity.TenantConst;
import com.ais.security.threatanalysis.util.TimeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.admin.indices.get.GetIndexRequest;
import org.elasticsearch.action.bulk.BackoffPolicy;
import org.elasticsearch.action.bulk.BulkProcessor;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.reindex.DeleteByQueryRequest;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.bucket.composite.CompositeAggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.composite.CompositeValuesSourceBuilder;
import org.elasticsearch.search.aggregations.bucket.composite.ParsedComposite;
import org.elasticsearch.search.aggregations.bucket.composite.TermsValuesSourceBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.Terms;
import org.elasticsearch.search.aggregations.metrics.Cardinality;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.SortOrder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author chaoyan
 * @date 2021/4/15
 */
@Service
public class ElasticSearchOperateServiceImpl {
    private final Logger log = LogManager.getLogger(ElasticSearchOperateServiceImpl.class);

    @Resource
    private RestHighLevelClient client;

    private BulkProcessor threatBulkProcessor;

    private BulkProcessor otherBulkProcessor;

    /**
     * ????????????????????????????????????
     *
     * @throws IOException
     */
    @PostConstruct
    public void initTemplate() throws IOException {

        // ?????????bulkProcessor
        threatBulkProcessor = getBulkProcessor(1000, 1, 10);
        otherBulkProcessor = getBulkProcessor(100000, 15, 60);
    }

    /**
     * ????????????????????????
     *
     * @param index
     * @return
     */
    public boolean indexExist(String index) {
        boolean exist = false;

        GetIndexRequest indexRequest = new GetIndexRequest().indices(index);
        try {
            exist = client.indices().exists(indexRequest, RequestOptions.DEFAULT);
        } catch (Exception e) {
            log.error("????????????" + index + "??????????????????????????????" + e.getMessage());
        }

        return exist;
    }

    /**
     * ??????????????????????????????
     *
     * @param indexName
     * @param indexMapping
     * @return
     */
    public boolean checkIndexExistAndCreate(String indexName, XContentBuilder indexMapping) {
        try {
            XContentBuilder indexSetting = XContentFactory.jsonBuilder()
                    .startObject()
                    .field("number_of_shards", "1")
                    .field("number_of_replicas", "0")
                    .field("max_result_window", 4000000)
                    //added by lijq on 20190516 begin...
                    .field("translog.durability", "async")
                    .field("translog.flush_threshold_size", "5000mb")
                    .field("mapping.nested_objects.limit", "200000")
                    // end.
                    .endObject();
            return checkIndexExistAndCreate(indexName, indexSetting, indexMapping);
        } catch (IOException e) {
            log.info("??????{}????????????????????????{}", indexName, e.getMessage());
            return false;
        }
    }

    /**
     * ?????????????????????????????????
     *
     * @param indexName
     * @param indexSetting
     * @param indexMapping
     * @return
     */
    public boolean checkIndexExistAndCreate(String indexName, XContentBuilder indexSetting, XContentBuilder indexMapping) {
        boolean exist = indexExist(indexName);

        if (!exist) {
            CreateIndexRequest request = new CreateIndexRequest(indexName);
            request.settings(indexSetting);
            request.mapping("_doc", indexMapping);
            CreateIndexResponse createIndexResponse;
            try {
                createIndexResponse = client.indices().create(request, RequestOptions.DEFAULT);
            } catch (IOException e) {
                log.info("??????{}????????????????????????{}", indexName, e.getMessage());
                return false;
            }

            return createIndexResponse.isAcknowledged();
        }

        return true;
    }

    /**
     * ????????????
     *
     * @param index
     */
    public void deleteIndex(String index) {
        if (!indexExist(index)) {
            return;
        }
        try {
            DeleteIndexRequest indexRequest = new DeleteIndexRequest().indices(index);
            client.indices().delete(indexRequest, RequestOptions.DEFAULT);
        } catch (Exception e) {
            log.warn("????????????" + index + "??????????????????" + e.getMessage());
        }
    }

    /**
     * ??????Term???????????????????????????key
     *
     * @param boolQuery
     * @param aggregation
     * @param key
     * @param indexNames
     * @return
     */
    public List<String> getAggregationKeyResult(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String key, String... indexNames) {
        try {
            SearchResponse searchResponse = executeAggWithoutHits(boolQuery, aggregation, indexNames);
            if (searchResponse == null) {
                return new ArrayList<>();
            }
            return getAggregationBucketKey(key, searchResponse);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return new ArrayList<>();
    }

    /**
     * ?????????????????????????????????hits??????
     *
     * @param boolQuery
     * @param aggregation
     * @param indices
     * @return
     * @throws IOException
     */
    private SearchResponse executeAggWithoutHits(BoolQueryBuilder boolQuery, AggregationBuilder aggregation,
                                                 String... indices) throws IOException {
        SearchSourceBuilder sourceBuilder = getSourceBuilder(boolQuery, aggregation);
        sourceBuilder.size(0);
        return executeSearch(sourceBuilder, indices);
    }

    /**
     * ????????????????????????????????????????????????ES???????????????
     *
     * @param boolQuery
     * @param aggregation
     * @return
     */
    private SearchSourceBuilder getSourceBuilder(BoolQueryBuilder boolQuery, AggregationBuilder aggregation) {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        if (boolQuery != null) {
            sourceBuilder.query(boolQuery);
        }
        if (aggregation != null) {
            sourceBuilder.aggregation(aggregation);
        }

        return sourceBuilder;
    }

    /**
     * ??????key?????????????????????
     *
     * @param boolQuery
     * @param aggregation
     * @param key
     * @param indexNames
     * @return
     */
    public Map<String, Object> getAggregationKeyResultAndTotal(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String key, String... indexNames) {
        Map<String, Object> result = new HashMap<>();
        try {
            SearchSourceBuilder sourceBuilder = getSourceBuilder(boolQuery, aggregation);
            sourceBuilder.size(0);
            sourceBuilder.aggregation(AggregationBuilders.cardinality("total").field(key).precisionThreshold(100000));
            SearchResponse searchResponse = executeSearch(sourceBuilder, indexNames);
            if (searchResponse == null) {
                return null;
            }

            List<String> list = getAggregationBucketKey(key, searchResponse);
            ;
            Cardinality total = searchResponse.getAggregations().get("total");
            result.put("total", total.getValue());
            result.put("data", list);
            return result;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private List<String> getAggregationBucketKey(String key, SearchResponse searchResponse) {
        Terms aggregationResult = searchResponse.getAggregations().get(key);
        List<? extends Terms.Bucket> buckets = aggregationResult.getBuckets();
        List<String> list = new ArrayList<>();
        for (Terms.Bucket tb : buckets) {
            list.add(tb.getKey().toString());
        }
        return list;
    }

    public long getBucketTotal(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String key, String... indexNames) {
        Map<String, Object> result = getAggregationKeyResultAndTotal(boolQuery, aggregation, key, indexNames);
        if (result == null || result.get("total") == null) {
            return 0;
        } else {
            return Long.parseLong(result.get("total").toString());
        }
    }

    public ParsedComposite searchCompositeAggregation(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String key, String... indexNames) {
        try {
            SearchResponse searchResponse = getSearchResponse(boolQuery, aggregation, indexNames);
            if (searchResponse == null || searchResponse.getHits() == null) {
                return null;
            }
            return searchResponse.getAggregations().get(key);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * ???????????????????????????????????????????????????
     *
     * @param queryBuilder
     * @param indices
     * @return
     * @throws IOException
     */
    private SearchResponse searchTotalHit(BoolQueryBuilder queryBuilder, String... indices) throws IOException {
        SearchSourceBuilder sourceBuilder = getSourceBuilder(queryBuilder, null);
        sourceBuilder.size(0);
        sourceBuilder.trackTotalHits(true);
        return executeSearch(sourceBuilder, indices);
    }

    /**
     * ???????????????????????????
     *
     * @param sourceBuilder
     * @param indices
     * @return
     * @throws IOException
     */
    public SearchResponse executeSearch(SearchSourceBuilder sourceBuilder, String... indices) throws IOException {
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indices);
        esRequest.source(sourceBuilder);
        return client.search(esRequest, RequestOptions.DEFAULT);
    }

    /**
     * ????????????
     *
     * @param boolQuery
     * @param aggregation
     * @param pageSize
     * @param pageNum
     * @param orderColumn
     * @param desc
     * @param indexNames
     * @return
     * @throws IOException
     */
    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, AggregationBuilder aggregation,
                                            Integer pageSize, Integer pageNum,
                                            String orderColumn, Boolean desc, String... indexNames) throws IOException {
        LinkedHashMap<String, Boolean> orderInfos = null;
        if (desc) {
            orderInfos = new LinkedHashMap<>();
            orderInfos.put(orderColumn, true);
        }

        return getSearchResponse(boolQuery, aggregation, pageSize, pageNum, orderInfos, indexNames);
    }

    /**
     * @param boolQuery
     * @param aggregation
     * @param pageSize
     * @param pageNum
     * @param orderInfos  key-???????????????value-????????????
     * @param indexNames
     * @return
     * @throws IOException
     */
    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, AggregationBuilder aggregation,
                                            Integer pageSize, Integer pageNum,
                                            LinkedHashMap<String, Boolean> orderInfos, String... indexNames)
            throws IOException {
        SearchSourceBuilder sourceBuilder = getSourceBuilder(boolQuery, aggregation);
        if (pageNum != null) {
            sourceBuilder.from((pageNum - 1) * pageSize);
            sourceBuilder.size(pageSize);
        }
        if (orderInfos != null) {
            for (Map.Entry<String, Boolean> entry : orderInfos.entrySet()) {
                sourceBuilder.sort(entry.getKey(), entry.getValue() ? SortOrder.DESC : SortOrder.ASC);
            }
        }
        sourceBuilder.trackTotalHits(true);
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        return client.search(esRequest, RequestOptions.DEFAULT);
    }


    /**
     * ????????????????????????
     *
     * @param boolQuery
     * @param aggregation
     * @param _source
     * @param orderColumn
     * @param desc
     * @param indexNames
     * @return
     */
    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String _source, String orderColumn, Boolean desc, String... indexNames) throws IOException {
        return getSearchResponse(boolQuery, aggregation, new String[]{_source}, orderColumn, desc, indexNames);
    }

    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String[] _sources, String orderColumn, Boolean desc, String... indexNames) throws IOException {
        SearchSourceBuilder sourceBuilder = getSourceBuilder(boolQuery, aggregation);

        if (desc) {
            sourceBuilder.sort(orderColumn, SortOrder.DESC);
        }
        sourceBuilder.trackTotalHits(true);
        sourceBuilder.fetchSource(_sources, null);
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        return client.search(esRequest, RequestOptions.DEFAULT);
    }

    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, int offset, int pageSize, int pageNum, String orderColumn, Boolean desc, String... indexNames) throws IOException {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        if (boolQuery != null) {
            sourceBuilder.query(boolQuery);
        }

        sourceBuilder.from((pageNum - 1) * pageSize + offset);
        sourceBuilder.size(pageSize);

        if (desc) {
            sourceBuilder.sort(orderColumn, SortOrder.DESC);
        }
        sourceBuilder.trackTotalHits(true);
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        return client.search(esRequest, RequestOptions.DEFAULT);
    }

    /**
     * ?????????????????????????????????
     *
     * @param indexNames
     * @return
     */
    public int getTotalHits(String... indexNames) {
        return getTotalHits(null, indexNames);
    }

    /**
     * ???????????????????????????????????????????????????
     *
     * @param queryBuilder
     * @param indices
     * @return
     */
    public int getTotalHits(BoolQueryBuilder queryBuilder, String... indices) {
        String[] existIndexArr = getExistIndex(indices);
        if (existIndexArr.length == 0) {
            return 0;
        }

        try {
            SearchResponse response = searchTotalHit(queryBuilder, indices);
            if (response == null || response.getHits() == null || response.getHits().getTotalHits() == null) {
                return 0;
            } else {
                return (int) response.getHits().getTotalHits().value;
            }
        } catch (IOException e) {
            log.error("???????????????????????????????????????{}", e.getMessage());
            return 0;
        }
    }

    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, AggregationBuilder aggregation,
                                            String... indexNames) throws IOException {
        SearchSourceBuilder sourceBuilder = getSourceBuilder(boolQuery, aggregation);
        sourceBuilder.size(0);

        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        return client.search(esRequest, RequestOptions.DEFAULT);
    }

    /**
     * ????????????????????????????????????????????????????????????3???
     *
     * @param boolQuery
     * @param aggregation
     * @param indexNames
     * @return
     */
    public SearchResponse getSearchResponseDaily(BoolQueryBuilder boolQuery, AggregationBuilder aggregation, String... indexNames) {
        SearchResponse response = null;
        int retries = 1;

        while (retries <= 3) {
            try {
                response = getSearchResponse(boolQuery, aggregation, indexNames);
                if (response != null) {
                    break;
                }
            } catch (Exception e) {
                log.error("??????es???????????????{}???????????????{}", retries, e.getMessage(), e);
                retries++;
                try {
                    Thread.sleep(retries * 15L * 1000);
                } catch (Exception ignore) {
                }
            }
        }

        return response;
    }

    /**
     * ???????????????????????????
     *
     * @param list
     * @param index
     */
    public void bulkPutIndex(List<Map<String, Object>> list, String index) {
        if (list.size() == 0) {
            return;
        }
        try {
            BulkRequest request = new BulkRequest();
            for (Map<String, Object> map : list) {
                request.add(new IndexRequest(index).source(map, XContentType.JSON));
            }
            client.bulk(request, RequestOptions.DEFAULT);
        } catch (Exception e) {
            log.error("?????????[{}]?????????????????????????????????:{}", index, e.getMessage(), e);
        }
    }

    /**
     * ???????????????????????????????????????
     *
     * @param startTime
     * @param endTime
     * @param indexName
     * @param timeKeyWord
     */
    public void deleteDataByTimeRange(String startTime, String endTime, String indexName, String timeKeyWord) {
        try {
            DeleteByQueryRequest request = new DeleteByQueryRequest();
            request.indices(indexName);
            request.setQuery(QueryBuilders.rangeQuery(timeKeyWord).gte(startTime).lt(endTime));
            client.deleteByQuery(request, RequestOptions.DEFAULT);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    public String[] getExistIndex(String[] indices) {
        List<String> existIndex = new ArrayList<>();
        for (String index : indices) {
            if (indexExist(index)) {
                existIndex.add(index);
            }
        }

        String[] existIndexArr = new String[existIndex.size()];
        existIndex.toArray(existIndexArr);

        return existIndexArr;
    }

    public String[] getIndices(Integer statPerid, String tenantId, String indexNamePrefix) {
        List<String> result = new ArrayList<>();
        String indexName;
        if (statPerid == TenantConst.StatPeriod.TODAY) {
            indexName = indexNamePrefix + tenantId + "-" + TimeUtils.getTodayDate();
            if (indexExist(indexName)) {
                result.add(indexName);
            }
        }
        if (statPerid == TenantConst.StatPeriod.YESTERDAY) {
            indexName = indexNamePrefix + tenantId + "-" + TimeUtils.getYesterdayDate();
            if (indexExist(indexName)) {
                result.add(indexName);
            }
        }
        if (statPerid == TenantConst.StatPeriod.LATEST_7_DAYS) {
            dealSevenMore(tenantId, indexNamePrefix, result, -6);

        }
        if (statPerid == TenantConst.StatPeriod.LATEST_30_DAYS) {
            dealSevenMore(tenantId, indexNamePrefix, result, -29);

        }
        if (statPerid == TenantConst.StatPeriod.LATEST_90_DAYS) {
            dealSevenMore(tenantId, indexNamePrefix, result, -89);
        }
        String[] indices = result.toArray(new String[result.size()]);
        return indices;
    }

    private void dealSevenMore(String tenantId, String indexNamePrefix, List<String> result, int end) {
        String indexName;
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, -1);
        Date endDate = calendar.getTime();
        calendar.add(Calendar.DAY_OF_MONTH, end);
        Date startDate = calendar.getTime();
        List<String> dateSpace = TimeUtils.getBetweenDates(startDate, endDate);
        for (String date : dateSpace) {
            indexName = indexNamePrefix + tenantId + "-" + date;
            if (indexExist(indexName)) {
                result.add(indexName);
            }
        }
    }

    public CompositeAggregationBuilder getCompositeAggregation(String[] compositeKeys, Map<String, Object> afterKey, int size) {
        List<CompositeValuesSourceBuilder<?>> sources = new ArrayList<>();
        for (String key : compositeKeys) {
            sources.add(new TermsValuesSourceBuilder(key).field(key));
        }

        CompositeAggregationBuilder compositeAggregation = new CompositeAggregationBuilder("compositeAggregation", sources)
                .size(size);
        if (afterKey != null) {
            compositeAggregation.aggregateAfter(afterKey);
        }

        return compositeAggregation;
    }

    public SearchHit[] getSearchHits(BoolQueryBuilder boolQuery, int from, int size, Map<String,SortOrder> descSortKey, String... indexNames) throws IOException {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        if (boolQuery != null) {
            sourceBuilder.query(boolQuery);
        }

        sourceBuilder.from(from);
        sourceBuilder.size(size);

        if (descSortKey != null && !descSortKey.isEmpty()) {
            Iterator<Map.Entry<String, SortOrder>> it =descSortKey.entrySet().iterator();
//            for (Set key : descSortKey.entrySet().iterator()) {
//                sourceBuilder.sort(key, SortOrder.DESC);
//            }
            while (it.hasNext())
            {
                Map.Entry<String, SortOrder> entry=it.next();
                sourceBuilder.sort(entry.getKey(),entry.getValue());
            }
        }
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        SearchResponse response = client.search(esRequest, RequestOptions.DEFAULT);
        if (response != null && response.getHits() != null) {
            return response.getHits().getHits();
        }

        return null;
    }

    public SearchHit[] getSearchHits(BoolQueryBuilder boolQuery, int size, Map<String,SortOrder> descSortKey, String... indexNames) throws IOException {
        return getSearchHits(boolQuery, 0, size, descSortKey, indexNames);
    }


    public SearchHits getSearchHitsInfo(BoolQueryBuilder boolQuery, int size, List<String> descSortKey, String[] displayKey, String indexNames) throws IOException {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        if (boolQuery != null) {
            sourceBuilder.query(boolQuery);
        }
        sourceBuilder.size(size);
        sourceBuilder.trackTotalHits(true);
        if (descSortKey != null && !descSortKey.isEmpty()) {
            for (String key : descSortKey) {
                sourceBuilder.sort(key, SortOrder.DESC);
            }
        }
        if (displayKey != null && displayKey.length > 0) {
            sourceBuilder.fetchSource(displayKey, null);
        }
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        SearchResponse response = client.search(esRequest, RequestOptions.DEFAULT);
        if (response != null && response.getHits() != null) {
            return response.getHits();
        }
        return null;
    }


    /**
     * ??????????????????????????????key??????
     * ????????????????????????????????????max_buckets?????????es????????????????????????????????????termsFunction?????????
     *
     * @param boolQuery     ??????
     * @param orderBy       ?????????
     * @param desc          ????????????
     * @param pageNum       ????????????????????????????????????????????????1?????????
     * @param pageSize      ??????????????????
     * @param termsFunction ???????????? ???Collectors.groupingBy(termsFunction, LinkedHashMap::new, Collectors.toList())???
     * @param total         ??????????????????????????????????????????????????????????????????desc????????????????????????????????????
     * @param indexs        ???????????????
     * @return ??????keys??????
     * @throws IOException
     */
    public List<String> getBatchQueryEsDataKeys(BoolQueryBuilder boolQuery, String orderBy, boolean desc, int pageNum, int pageSize, Function<SearchHit, String> termsFunction, Integer total, String... indexs) throws IOException {

        int PAGE_SIZE = 10000;

        int currentIndex = 0;
        int start = (pageNum - 1) * pageSize + 1;
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(boolQuery);
        Object[] searchAfter = null;
        searchSourceBuilder.size(PAGE_SIZE);

        if (total != null && start * 2 > total) {
            // ???????????????????????????????????????????????????
            searchSourceBuilder.sort(orderBy, desc ? SortOrder.ASC : SortOrder.DESC);
            start = total - (pageSize * pageNum) + 1;
            if (start < 1) {
                // start??????1???????????????????????????????????????pageSize???????????????????????????pageSize
                pageSize = total - (pageSize * (pageNum - 1));
                start = 1;
            }
        } else {
            searchSourceBuilder.sort(orderBy, desc ? SortOrder.DESC : SortOrder.ASC);
        }

        searchSourceBuilder.sort("_id");

        return calculateKeys(pageSize, termsFunction, currentIndex, start, searchSourceBuilder, searchAfter, indexs);


    }

    private List<String> calculateKeys(int pageSize, Function<SearchHit, String> termsFunction, int currentIndex, int start, SearchSourceBuilder searchSourceBuilder, Object[] searchAfter, String[] indexs) throws IOException {
        Set<String> keySet = new HashSet<>();
        List<String> keys = new ArrayList<>();
        out:
        while (true) {

            Optional.ofNullable(searchAfter).ifPresent(searchSourceBuilder::searchAfter);

//            ((TermsAggregationBuilder) aggregation).size(100000);
//            List<FieldSortBuilder> sortBuilders = new ArrayList<>();
//            sortBuilders.add(new FieldSortBuilder(orderBy).order(desc ? SortOrder.DESC : SortOrder.ASC));
//            BucketSortPipelineAggregationBuilder page = PipelineAggregatorBuilders.bucketSort("page", sortBuilders).from((PAGE_NUM - 1) * PAGE_SIZE).size(PAGE_SIZE);
//            aggregation.subAggregation(page);
            SearchResponse searchResponse = executeSearch(searchSourceBuilder, indexs);
            SearchHits hits = searchResponse.getHits();
            SearchHit[] searchHits = hits.getHits();
            LinkedHashMap<String, List<SearchHit>> linkedHashMap = Arrays.stream(searchHits).collect(Collectors.groupingBy(termsFunction, LinkedHashMap::new, Collectors.toList()));
            if (linkedHashMap.size() == 0) {
                break;
            }
            for (Map.Entry<String, List<SearchHit>> item : linkedHashMap.entrySet()) {
                if (!keySet.add(item.getKey())) {
                    continue;
                }
                currentIndex++;
                if (currentIndex >= start) {
                    keys.add(item.getKey());
                }
                if (keys.size() >= pageSize) {
                    break out;
                }
            }
            searchAfter = searchHits[searchHits.length - 1].getSortValues();
        }
        return keys;
    }

    private BulkProcessor getBulkProcessor(int bulkNum, int bulkSizeMb, int bulkTimeSecond) {
        BiConsumer<BulkRequest, ActionListener<BulkResponse>> bulkConsumer =
                (request, bulkListener) -> client.bulkAsync(request, RequestOptions.DEFAULT, bulkListener);

        return BulkProcessor.builder(bulkConsumer, new BulkProcessor.Listener() {
                    @Override
                    public void beforeBulk(long executionId, BulkRequest request) {
                        // default implementation ignored
                    }

                    @Override
                    public void afterBulk(long executionId, BulkRequest request, BulkResponse response) {
                        log.info("????????????[{}],??????[{}],??????[{}],??????[{}]",
                                String.join(",", request.getIndices()),
                                request.numberOfActions(),
                                !response.hasFailures() ? "??????" : "??????",
                                response.getTook().toString());
                    }

                    @Override
                    public void afterBulk(long executionId, BulkRequest request, Throwable failure) {
                        log.error("??????ES??????????????????{}", failure.getMessage());
                    }

                })
                // ?????????????????????
                .setBulkActions(bulkNum)
                // ?????????????????????
                .setBulkSize(new ByteSizeValue(bulkSizeMb, ByteSizeUnit.MB))
                // ???????????????????????????
                .setFlushInterval(TimeValue.timeValueSeconds(bulkTimeSecond))
                //???????????????
                .setConcurrentRequests(2)
                // ??????????????????
                .setBackoffPolicy(BackoffPolicy.exponentialBackoff(TimeValue.timeValueSeconds(1), 3))
                .build();
    }

    public synchronized void bulkPutIndex_new(Map<String, Object> map, String index, boolean isThreat) {
        if (isThreat) {
            threatBulkProcessor.add(new IndexRequest(index).source(map, XContentType.JSON));
        } else {
            otherBulkProcessor.add(new IndexRequest(index).source(map, XContentType.JSON));
        }
    }

    public SearchResponse getSearchResponse(BoolQueryBuilder boolQuery, AggregationBuilder[] aggregationBuilders, String indexNames) throws IOException {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        if (boolQuery != null) {
            sourceBuilder.query(boolQuery);
        }
        sourceBuilder.size(0);
        if (aggregationBuilders != null && aggregationBuilders.length > 0) {
            for (AggregationBuilder agg : aggregationBuilders) {
                sourceBuilder.aggregation(agg);
            }
        }
        SearchRequest esRequest = new SearchRequest();
        esRequest.indices(indexNames);
        esRequest.source(sourceBuilder);
        return client.search(esRequest, RequestOptions.DEFAULT);
    }
}
