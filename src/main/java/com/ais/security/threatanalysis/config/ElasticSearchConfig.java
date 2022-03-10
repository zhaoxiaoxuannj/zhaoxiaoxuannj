package com.ais.security.threatanalysis.config;

import org.apache.http.HttpHost;
import org.elasticsearch.client.RestHighLevelClient;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * @author chaoyan
 * @date 2020/5/20
 */
@Configuration
public class ElasticSearchConfig {
    static {
        System.setProperty("es.set.netty.runtime.available.processors", "false");
    }

    @Value("${elasticSearch.server.hosts}")
    private String esAddrs;

    @Value("${elasticSearch.server.username}")
    private String userName;

    @Value("${elasticSearch.server.password}")
    private String password;


    @Bean
    public RestHighLevelClient restHighLevelClient() {
        return getEsClientDecorator().getRestHighLevelClient();
    }

    @Bean
    @Scope("singleton")
    public ESClientDecorator getEsClientDecorator() {
        String[] esHostInfos = esAddrs.split(",");
        HttpHost[] hosts = new HttpHost[esHostInfos.length];
        for (int i = 0; i < esHostInfos.length; i++) {
            String[] serverInfo = esHostInfos[i].split(":");
            hosts[i] = new HttpHost(serverInfo[0], Integer.parseInt(serverInfo[1]));
        }
        return new ESClientDecorator(hosts, userName, password);
    }

}
