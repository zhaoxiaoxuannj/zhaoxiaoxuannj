package com.ais.security.threatanalysis;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import org.mybatis.spring.annotation.MapperScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableEncryptableProperties
@MapperScan(basePackages = "com.ais.security.threatanalysis.mapper")
public class DemoApplication {

    private static Logger log = LoggerFactory.getLogger(DemoApplication.class);


    public static void main(String[] args) {
            SpringApplication.run(DemoApplication.class, args);
    }

}
