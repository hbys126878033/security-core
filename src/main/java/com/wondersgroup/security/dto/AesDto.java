package com.wondersgroup.security.dto;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author chenlin
 * @create 2019-12-30 9:54
 * @description: AES
 * @version：1.0
 **/
@Data
@Accessors(chain = true)
public class AesDto {

    /**
     * 表示java加密后的信息
     * */
    private String encrypt;

    /**
     * 表示js加密后，java解密后的内容
     * */
    private String decrypt;

    /**
     * 待java加密的信息
     */
    private String message;
    /**
     * java 加密使用的密钥
     * */
    private String key;
}
