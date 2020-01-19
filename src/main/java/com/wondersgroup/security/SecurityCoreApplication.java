package com.wondersgroup.security;

import com.wondersgroup.security.intercepter.CryptoFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.batch.BatchDataSource;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityCoreApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityCoreApplication.class, args);
    }


    //@Bean
    public FilterRegistrationBean cryptoFilter(){
        FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new CryptoFilter());
        filter.addUrlPatterns("/*");
        filter.setName("cryptpFilter");
        filter.setOrder(1);
        return filter;
    }
}
