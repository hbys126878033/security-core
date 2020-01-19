package com.wondersgroup.security.dto;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author chenlin
 * @create 2019-12-31 13:41
 * @description: TODO
 * @version：1.0
 **/
@Data
@Accessors(chain = true)
public class RsaAndAesDto {
    /**返回后台的标识 ，true表示成功，false表示失败*/
    public Boolean success;
    /**
     * 加密后的数据
     * */
    public String _encryptData;
    /**AES算法加密的密钥，但是该密钥通过RSA算法加密了，使用时请先解密*/
    public String _key;
    /** 客户端加密语言，1表示javascript*/
    public String _flag;
}
