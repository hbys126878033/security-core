package com.wondersgroup.security.intercepter;

import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RsaUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.springframework.util.StringUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @author chenlin
 * @create 2019-12-31 15:05
 * @description: 结合 @Crypto 注解，实现统一解密的功能
 * @version：1.0
 **/
@Slf4j
public class CryptInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //response.setHeader("Set-Cookie", "name=value; HttpOnly"); //向所有会话cookie中添加“HttpOnly”属性。

        if (handler instanceof HandlerMethod) {
            HandlerMethod hm = (HandlerMethod)handler;
            Crypto crypto = hm.getMethodAnnotation(Crypto.class);
            if (crypto != null) {
                BCRSAPrivateCrtKey privateKey = RsaUtils.getPrivateKey();
                String privateKeyString = RsaUtils.encodeKey2String(privateKey.getEncoded());
                AsymmetricKeyParameter keyParameter = RsaUtils.getPrivateKeyParameter(privateKeyString);
                /** 固定的参数处理 _flag,_key,_encryptData*/
                String _flag = request.getParameter("_flag");
                String _encryptData = request.getParameter("_encryptData");
                String _key = request.getParameter("_key");

                /** 当这三者都有值时才执行解密的逻辑 */
                if(StringUtils.hasText(_flag) && StringUtils.hasText(_encryptData) && StringUtils.hasText(_key)){
                    String aesKey = null;
                    if ("1".equals(_flag)) {
                        aesKey = RsaUtils.decryptFromJavascript(_key,keyParameter);
                    } else  {
                        aesKey = RsaUtils.decrypt4Base64(_key,keyParameter);
                    }
                    String decrypt = AesUtils.decrypt(_encryptData, aesKey);
                    log.info("解密后 =>：{}",decrypt);
                    Map<String,String[]> param = new HashMap<String,String[]>();
                    param.put("decrypt",new String[]{decrypt});
                    /** reqeust对象重新包装一下 */
                    request = new CryptRequestWrapper(request,param);
                    //request.getRequestDispatcher(request.getRequestURI()).forward(request, response);
                    //return false;
                }

            }
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {


    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    }
}
