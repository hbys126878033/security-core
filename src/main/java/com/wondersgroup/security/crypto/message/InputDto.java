package com.wondersgroup.security.crypto.message;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;

/**
 * @author chenlin
 * @create 2020-01-19 9:48
 * @description: 前端加密后使用JSON提交参数，在DecryptRequestBodyAdvice 中，尝试把JSON序列化成该对象
 * @version：1.0
 **/

@Data
@Accessors(chain = true)
public class InputDto implements Serializable {

    /**加密后的业务参数*/
    private String encryptData;
    /** AES 加密的密钥信息 ，但是用RSA公钥加密了*/
    private String encryptKey;
    /** 加密的方式 1 javascript 2 java */
    private String encryptFlag;
}
