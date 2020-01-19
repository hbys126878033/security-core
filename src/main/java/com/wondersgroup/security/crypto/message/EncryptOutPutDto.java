package com.wondersgroup.security.crypto.message;

import lombok.Data;

import java.io.Serializable;

/**
 * @author chenlin
 * @create 2020-01-02 9:31
 * @description: 加密后返回客户端的数据传输对象，
 *              controller中使用@ResponseBody标注
 *              加上@EncryptAndDecrypt和@Encrypt二选一
 *              再加上返回值是OutPutDto的才会执行加密算法
 * @version：1.0
 **/
@Data
public class EncryptOutPutDto implements Serializable {

    /**后台处理成功或者失败的标志*/
    private Boolean success;
    /**后台返回客户端的数据,使用了加密算法*/
    private String encryptData;
    /**提示信息，失败的话会给出相应的提示*/
    private String message;
    /**aes 算法的密钥*/
    private String key;

    public EncryptOutPutDto(){
        this.success = true;
    }

}
