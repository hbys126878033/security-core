package com.wondersgroup.security;

import com.wondersgroup.security.intercepter.CryptInterceptor;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author chenlin
 * @create 2019-12-31 15:28
 * @description: springMvc定制特性
 * @version：1.0
 **/

@Configuration
public class SpringMvcConfig
        implements WebMvcConfigurer
       // extends WebMvcConfigurationSupport
{
   @Override
    public void addInterceptors(InterceptorRegistry registry) {
       // CryptInterceptor crypt = new CryptInterceptor();
        //registry.addInterceptor(crypt).addPathPatterns("/**").excludePathPatterns("/js/**");

    }

   /*@Override
    protected void addInterceptors(InterceptorRegistry registry) {
        super.addInterceptors(registry);
        CryptInterceptor ctypt = new CryptInterceptor();
        registry.addInterceptor(ctypt).addPathPatterns("/**").excludePathPatterns("/js/**");

    }

    @Override
    protected void addResourceHandlers(ResourceHandlerRegistry registry) {
        super.addResourceHandlers(registry);
        //静态资源的映射
        System.out.println("配置了");
        registry.addResourceHandler("/")
                .addResourceLocations("classpath:/static/");
        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/");
    }*/
}


