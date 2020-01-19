package com.wondersgroup.security.crypto.core;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author chenlin
 * @create 2019-12-20 16:21
 * @description: AES 对称加密算法帮助类
 *              对称加密的密钥是一样,即加密和解密是用同一套密钥
 *
 * @version：1.0
 **/
public abstract class AESUtilsOld {

    /** 算法，加码模式，然后补位方式*/
    private static final String INSTANCE_KEY = "AES/CBC/PKCS5Padding";

    /** 使用AES-128-CBC加密模式，key需要为16位,key和iv可以相同！*/
    private static final String DEFAULT_KEY = "qazwsx1234edcrfv";

    private static final String IV_KEY = "plmokn9876ijbuhv";

    private static final String CHARSET_NAME = "utf-8";

    /**
     * 方法作用：  AES 加密算法
     * @param content 待加密的内容
     * @param key     加密的字符串
     * @return: java.lang.String
     * @createDate:  2019/12/20 16:56
     * @createAuthor: chenlin
     * @updateDate:  2019/12/20 16:56
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String encrypt(String content,String key){
        try {
            Cipher cipher = Cipher.getInstance(INSTANCE_KEY);
            /*// AES/CBC/PKCS5Padding 算法模式为CBC可以增加偏移量，可增加加密算法强度*/
            //IvParameterSpec iv = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"),getIvSpec(key));
            byte[] bytes = cipher.doFinal(content.getBytes(CHARSET_NAME));
            System.out.println("byte size = "+ bytes.length);
            String s = Base64.getEncoder().encodeToString(bytes);
            System.out.println("s size = "+ s.length());
            return s;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("AES加密出错...");
        }
    }

    /**
     * 方法作用：AES加密算法
     * @param content
     * @return: java.lang.String
     * @createDate:  2019/12/20 16:57
     * @createAuthor: chenlin
     * @updateDate:  2019/12/20 16:57
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String encrypt(String content){
        return encrypt(content,DEFAULT_KEY);
    }

    /**
     * 方法作用：AES 解密算法
     * @param content
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/20 17:22
     * @createAuthor: chenlin
     * @updateDate:  2019/12/20 17:22
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String decrypt(String content,String key){
        try {
            Cipher cipher = Cipher.getInstance(INSTANCE_KEY);
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keyspec,getIvSpec(key));
            byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(content.getBytes(CHARSET_NAME)));
            return new String(bytes,CHARSET_NAME);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("AES解密出错...");
        }
    }

    /**
     * 方法作用：AES 解密算法
     * @param content
     * @return: java.lang.String
     * @createDate:  2019/12/20 17:26
     * @createAuthor: chenlin
     * @updateDate:  2019/12/20 17:26
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String decrypt(String content){
         return decrypt(content,DEFAULT_KEY);
    }



    public static String initKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        /***AES 要求密钥长度是128,192或者256位，由于JDK只支持128位的密钥所以当前采用128位的*/
        kg.init(128);
        SecretKey secretKey = kg.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static IvParameterSpec getIvSpec(String key){
        byte[] data = null;
        if (key == null) {
            key = "";
        }
        StringBuffer sb = new StringBuffer(16);
        sb.append(key);
        while (sb.length() < 16) {
            sb.append("0");
        }
        if (sb.length() > 16) {
            sb.setLength(16);
        }
        try {
            data = sb.toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new IvParameterSpec(data);
    }

    public static void main(String[] args) throws Exception {

        String key = initKey();
        System.out.println(key+"====>;"+key.length());
        String content = "{\"name\":\" !#%$^&*()唐氏综合征[{先天愚型}]```<.?;'< = @/ \"}";
        String encrypt = encrypt(content,key);
        System.out.println(content+" || 加密后为 ===> "+encrypt);

        String decrypt = decrypt(encrypt,key);

        System.out.println(content+" || 加密后为 ===> "+encrypt+" || 重新解密后===>"+decrypt);


    }

}
