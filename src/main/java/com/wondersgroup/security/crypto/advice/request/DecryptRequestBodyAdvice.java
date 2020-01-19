package com.wondersgroup.security.crypto.advice.request;

import com.wondersgroup.security.crypto.annotation.Decrypt;
import com.wondersgroup.security.crypto.annotation.EncryptAndDecrypt;
import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RsaUtils;
import com.wondersgroup.security.crypto.message.InputDto;
import com.wondersgroup.security.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonInputMessage;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.nio.charset.Charset;

/**
 * @author chenlin
 * @create 2020-01-02 8:48
 * @description: 对标注了@RequestBody的参数进行额外处理，即解密
 *
 *   https://blog.csdn.net/f641385712/article/details/101396307
 *   http://www.throwable.club/2019/11/29/spring-mvc-param-global-encryption-decryption-in-action/
 *
 *   http://throwable.coding.me/2019/11/29/spring-mvc-param-global-encryption-decryption-in-action/
 * @version：1.0
 **/
@ControllerAdvice
@Slf4j
public class DecryptRequestBodyAdvice implements RequestBodyAdvice {

    private Boolean decrypted = false ;

    @Override
    public boolean supports(MethodParameter methodParameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        Method method = methodParameter.getMethod();
        if ( method.isAnnotationPresent(Decrypt.class) ||
                ( method.isAnnotationPresent(EncryptAndDecrypt.class) &&
                        method.getAnnotation(EncryptAndDecrypt.class).decrypt())) {
            log.info("该请求需要解密，请您稍等下");
            decrypted = true;
        }
        return decrypted;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        if(decrypted){

            String content = StreamUtils.copyToString(inputMessage.getBody(), Charset.forName("UTF-8"));
            log.info("Content: {}",content);
            InputDto inputDto = JsonUtil.decode(content, InputDto.class);
            log.info("InputDto:{}",inputDto);

            if (inputDto.getEncryptData() != null) {
                if (StringUtils.hasText(inputDto.getEncryptFlag()) && StringUtils.hasText(inputDto.getEncryptFlag())) {
                    BCRSAPrivateCrtKey privateKey = RsaUtils.getPrivateKey();
                    String privateKeyString = RsaUtils.encodeKey2String(privateKey.getEncoded());
                    AsymmetricKeyParameter keyParameter = RsaUtils.getPrivateKeyParameter(privateKeyString);
                    String aesKey = "";
                    if (inputDto.getEncryptFlag().equals("1")) {
                        aesKey = RsaUtils.decryptFromJavascript(inputDto.getEncryptKey(),keyParameter);
                    } else {
                        aesKey = RsaUtils.decrypt4Base64(inputDto.getEncryptKey(),keyParameter);
                    }
                    String data = AesUtils.decrypt(inputDto.getEncryptData(),aesKey);
                    ByteArrayInputStream in = new ByteArrayInputStream(data.getBytes("utf-8"));
                    return new MappingJacksonInputMessage(in,inputMessage.getHeaders());
                }
            }
        }
        return inputMessage;
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }
}
