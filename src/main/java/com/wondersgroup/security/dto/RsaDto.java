package com.wondersgroup.security.dto;

import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serializable;

/**
 * @author chenlin
 * @create 2019-12-26 15:23
 * @description: RSA 密钥信息
 * @version：1.0
 **/
@Data
@Accessors(chain=true)
public class RsaDto implements Serializable {
    /*公钥的模*/
    private String publicModulus;
    /*公钥的指数*/
    private String publicExponent;
    /*公钥*/
    private String publicKey;

}
