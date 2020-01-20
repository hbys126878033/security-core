package com.wondersgroup.security;

import com.wondersgroup.security.crypto.filter.DecryptFilter;
import com.wondersgroup.security.intercepter.CryptoFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.batch.BatchDataSource;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import javax.servlet.FilterRegistration;
import java.util.HashMap;

@SpringBootApplication
public class SecurityCoreApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityCoreApplication.class, args);
    }


    @Bean
    public FilterRegistrationBean decryptFilter(){
        FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new DecryptFilter());
        filter.setName("decryptFilter");
        filter.setOrder(1);
        filter.addUrlPatterns("/*");
        filter.addInitParameter("enabledXss","false");
        return filter;
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
