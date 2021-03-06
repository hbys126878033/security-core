package com.wondersgroup.security.crypto.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author chenlin
 * @create 2020-01-02 9:01
 * @description: 加解密的注解类
 * @version：1.0
 **/
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD,ElementType.TYPE})
public @interface EncryptAndDecrypt {

    /*是否需要加密*/
    boolean encrypt() default true;
    /*是否需要解密*/
    boolean decrypt() default true;
}
