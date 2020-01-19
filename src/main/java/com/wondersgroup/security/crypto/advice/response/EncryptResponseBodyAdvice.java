package com.wondersgroup.security.crypto.advice.response;

import com.wondersgroup.security.crypto.annotation.Encrypt;
import com.wondersgroup.security.crypto.annotation.EncryptAndDecrypt;
import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RsaUtils;
import com.wondersgroup.security.crypto.message.EncryptOutPutDto;
import com.wondersgroup.security.crypto.message.OutPutDto;
import com.wondersgroup.security.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.lang.reflect.Method;

/**
 * @author chenlin
 * @create 2019-12-31 23:00
 * @description: 请求响应处理类 对加了@crypto的方法的数据进行加密操作
 * @version：1.0
 **/

@ControllerAdvice
@Slf4j
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    private Boolean encrypted = false ;

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        Method method = returnType.getMethod();
        if ( method.isAnnotationPresent(Encrypt.class) ||
                ( method.isAnnotationPresent(EncryptAndDecrypt.class) &&
                        method.getAnnotation(EncryptAndDecrypt.class).encrypt())) {
            encrypted = true;
        }
        return encrypted;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        /*方法上标注了 @Encrypt 或者@EnctyptAndDecrypt 注解*/
        if (encrypted) {
            /*方法的返回值是OutPutDto类型的*/
            if (body instanceof OutPutDto) {
                OutPutDto outPut = (OutPutDto) body;
                /*后台处理逻辑失败时，默认不加密处理*/
                if (!outPut.getSuccess()){
                    return body;
                } else {
                    /*待加密的对象*/
                    Object encryptData = outPut.getData();
                    /*待加密的对象为空时，直接返回*/
                    if (encryptData == null) {
                        return body;
                    }
                    /*加密后的返回值*/
                    EncryptOutPutDto dto = new EncryptOutPutDto();
                    /* 暂时返回值是string 特殊处理下*/
                    if (encryptData instanceof String) {
                        dto.setEncryptData((String) encryptData);
                    }else{
                        dto.setEncryptData(JsonUtil.encodeString( encryptData));
                    }
                    /*rsa 私钥对象*/
                    BCRSAPrivateCrtKey privateKey = RsaUtils.getPrivateKey();
                    /*rsa 私钥字符串*/
                    String privateKeyString = RsaUtils.encodeKey2String(privateKey.getEncoded());
                    /*rsa 私钥的参数对象*/
                    AsymmetricKeyParameter keyParameter = RsaUtils.getPrivateKeyParameter(privateKeyString);
                    /* aes的密钥*/
                    String aesKey = AesUtils.initKey();
                    /*执行加密算法*/
                    dto.setEncryptData(AesUtils.encrypt(dto.getEncryptData(),aesKey));
                    if (StringUtils.hasText(outPut.getFlag())) {
                        switch (outPut.getFlag()){
                            case "1" :
                                dto.setKey(RsaUtils.encrypt4Javascript(aesKey, keyParameter));
                                break;
                            case "2" :
                                dto.setKey(RsaUtils.encrypt4Base64(aesKey, keyParameter));
                                break;
                            default :
                                throw new RuntimeException("客户端解密方式未配置，请您检查");
                        }
                    } else {
                        throw new RuntimeException("请您配置客户端解码的方式");
                    }

                    log.info("加密后为:{}",dto);
                    return dto;
                }
            }
        }
        return body;

    }
}
