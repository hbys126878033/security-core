package com.wondersgroup.security.crypto.message;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;

/**
 * @author chenlin
 * @create 2020-01-02 9:24
 * @description: controller中返回的数据的数据传输对象
 * @version：1.0
 **/
@Data
@Accessors(chain = true)
public class OutPutDto implements Serializable {

    /**后台处理成功或者失败的标志*/
    private Boolean success;
    /**后台返回客户端的数据*/
    private Object data;
    /**提示信息，失败的话会给出相应的提示*/
    private String message;
    /**客户端解密使用的语言，1表示javascript 2 表示java*/
    private String flag;

    public OutPutDto(){
        this.flag = "1";
    }

}
