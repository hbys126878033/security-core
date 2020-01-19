package com.wondersgroup.security.crypto.filter;

import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RsaUtils;
import com.wondersgroup.security.intercepter.CryptRequestWrapper;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
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
 * @version：1.0
 **/
@Component
@WebFilter(filterName="decryptFilter",urlPatterns = "/*")
@Order(1)
public class DecryptFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

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
            String decrypt = AesUtils.decrypt(encryptData, aesKey);
            Map<String,String[]> param = new HashMap<>(request.getParameterMap().size() + 2);
            param.put("decrypt",new String[]{decrypt});
            /* request对象重新包装一下,后面使用request的时候就是使用当前包装的对象*/
            CryptRequestWrapper cryptRequest = new CryptRequestWrapper(request,param);
            filterChain.doFilter(cryptRequest,response);
        } else {
            filterChain.doFilter(request,response);
        }
    }
}
