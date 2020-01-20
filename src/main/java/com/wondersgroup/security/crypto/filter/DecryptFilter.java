package com.wondersgroup.security.crypto.filter;

import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RsaUtils;
import com.wondersgroup.security.util.JsonUtil;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author chenlin
 * @create 2020-01-02 9:08
 * @description: 解密算法的Filter：
 *               SpringBoot 配置filter两种方式：
 *               1) 注解：@WebFilter 记得加上spring的注解@Component，把当前组件加入到IOC容器中
 *               2）配置类：FilterRegistrationBean类来注册filter
 *
 *              注意，当前版本中如果使用注解的话，是不能配置初始化参数的，请使用配置类的形式,配置类型setFilter时直接new DecryptFilter()，
 *                  不通过IOC容器管理当前的filter,也就不会执行GenericFilterBean中的afterPropertiesSet()方法
 *
 * @version：1.0
 **/
/*@Component
@WebFilter(filterName="decryptFilter",urlPatterns = "/*",initParams = {@WebInitParam(name="enabledXss",value="true")})
@Order(1)*/
public class DecryptFilter extends OncePerRequestFilter {


    private String enabledXss = "false";

    @Override
    protected void initFilterBean() throws ServletException {
        FilterConfig filterConfig = super.getFilterConfig();
        if(filterConfig != null){
            enabledXss = filterConfig.getInitParameter("enabledXss");
            if (!StringUtils.hasText(enabledXss)) {
                enabledXss = "false";
            }
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /**页面只能被本站页面嵌入到iframe或者frame中；*/
        response.setHeader("X-Frame-Options", "SAMEORIGIN");
        /** 浏览器根据给出的MIME类型来解析文档*/
        response.setHeader("X-Content-Type-Options", "nosniff");
        /** 1; mode=block：启用XSS保护，并在检查到XSS攻击时，停止渲染页面（例如IE8中，检查到攻击时，整个页面会被一个#替换*/
        response.setHeader("X-XSS-Protection", "1;mode=block");
        if("HTTPS".endsWith(request.getScheme().toUpperCase())){
            response.setHeader("Set-Cookie", "JSESSIONID=" + request.getSession().getId() + ";Secure;HttpOnly");
        }else{
            response.setHeader("Set-Cookie", "JSESSIONID=" + request.getSession().getId() + ";HttpOnly");
        }

        BCRSAPrivateCrtKey privateKey = RsaUtils.getPrivateKey();
        String privateKeyString = RsaUtils.encodeKey2String(privateKey.getEncoded());
        AsymmetricKeyParameter keyParameter = RsaUtils.getPrivateKeyParameter(privateKeyString);
        /* 固定的参数处理 flag,key,encryptData*/
        String flag = request.getParameter("_flag");
        String encryptData = request.getParameter("_encryptData");
        String key = request.getParameter("_key");

        /*当这三者都有值时才执行解密的逻辑*/
        if(StringUtils.hasText(flag) && StringUtils.hasText(encryptData) && StringUtils.hasText(key)){
            String aesKey = "";
            if ("1".equals(flag)) {
                aesKey = RsaUtils.decryptFromJavascript(key,keyParameter);
            } else  {
                aesKey = RsaUtils.decrypt4Base64(key,keyParameter);
            }

            /** 完全解密后的业务参数 */
            String decrypt = AesUtils.decrypt(encryptData, aesKey);
            /* request对象重新包装一下,后面使用request的时候就是使用当前包装的对象*/
            DecryptRequestWrapper cryptRequest = new DecryptRequestWrapper(request,JsonUtil.decode2MapObject(decrypt),Boolean.valueOf(this.enabledXss));
            filterChain.doFilter(cryptRequest,response);
        } else {
            filterChain.doFilter(request,response);
        }
    }
}
