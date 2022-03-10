package com.ais.security.threatanalysis.config;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

/**
 * @author chaoyan
 * @date 2020/5/20
 */
public class ESClientDecorator implements InitializingBean, DisposableBean {

    private RestHighLevelClient restHighLevelClient=null;

    private HttpHost[] httpHosts;

    private String userName;

    private String password;



    public ESClientDecorator(HttpHost[] httpHosts, String userName, String password) {
        this.httpHosts = httpHosts;
        this.userName = userName;
        this.password = password;
    }

    public RestHighLevelClient getRestHighLevelClient() {
        if (restHighLevelClient == null) {
            RestClientBuilder builder = RestClient.builder(httpHosts);
            builder.setRequestConfigCallback(
                    new RestClientBuilder.RequestConfigCallback() {
                        @Override
                        public RequestConfig.Builder customizeRequestConfig(
                                RequestConfig.Builder requestConfigBuilder) {
                            return requestConfigBuilder
                                    .setConnectTimeout(2 * 60 * 1000)
                                    //更改客户端的超时限制默认30秒现在改为20分钟
                                    .setSocketTimeout(20 * 60 * 1000);
                        }
                    });
            if (!StringUtils.isEmpty(userName) && !StringUtils.isEmpty(password)) {
                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(userName, password));
                builder.setHttpClientConfigCallback(f -> f.setDefaultCredentialsProvider(credentialsProvider));
            }
            restHighLevelClient = new RestHighLevelClient(builder);
        }
        return restHighLevelClient;
    }


    @Override
    public void destroy() throws Exception {
        restHighLevelClient.close();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        RestClientBuilder builder = RestClient.builder(httpHosts)
                .setRequestConfigCallback(
                        new RestClientBuilder.RequestConfigCallback() {
                            @Override
                            public RequestConfig.Builder customizeRequestConfig(
                                    RequestConfig.Builder requestConfigBuilder) {
                                return requestConfigBuilder
                                        .setConnectTimeout(20601000)
                                        //更改客户端的超时限制默认30秒现在改为20分钟
                                        .setSocketTimeout(20601000);
                            }
                        });
        if (!StringUtils.isEmpty(userName) && !StringUtils.isEmpty(password)) {
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(userName, password));
            builder.setHttpClientConfigCallback(f -> f.setDefaultCredentialsProvider(credentialsProvider));
        }
        restHighLevelClient = new RestHighLevelClient(builder);
    }

}
