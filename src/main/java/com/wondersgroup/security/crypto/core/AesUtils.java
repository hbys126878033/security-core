package com.wondersgroup.security.crypto.core;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author chenlin
 * @create 2019-12-20 16:21
 * @description: AES 对称加密算法帮助类
 *              对称加密的密钥是一样,即加密和解密是用同一套密钥
 *
 * @version：1.0
 **/
public abstract class AesUtils {

    /** 算法，加码模式，然后补位方式  PKCS5Padding 是 PKCS5Padding
     *
     *
     *  补位方式：
     *      ZeroPadding：数据长度不对齐时使用0填充，否则不填充。
     *      PKCS7Padding：假设每个区块大小为blockSize
     *                      <1>已对齐，填充一个长度为blockSize且每个字节均为blockSize的数据。
     *                      <2>未对齐，需要补充的字节个数为n，则填充一个长度为n且每个字节均为n的数据。
     *      PKCS5Padding：PKCS5Padding，PKCS7Padding的子集，只是块大小固定为8字节(两者的区别在于PKCS5Padding是限制块大小的PKCS7Padding)
     * */
    private static final String INSTANCE_KEY = "AES/CBC/PKCS5Padding";

    /** 使用AES-128-CBC加密模式，key需要为16位,key和iv可以相同！*/
    private static final String DEFAULT_KEY = "qazwsx1234edcrfv";


    private static final String IV_KEY = "plmokn9876ijbuhv";

    private static final String CHARSET_NAME = "utf-8";

    /**
     * 方法作用：
     * @param data
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/30 10:42
     * @createAuthor: chenlin
     * @updateDate:  2019/12/30 10:42
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String encrypt(String data,String key){
        try {
            return encrypt2String(data.getBytes(CHARSET_NAME),key);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException("AES加密时,字符串转换成字节数组出错...",e);
        }
    }
    public static byte[] encrypt(byte[] data,String key){
        try {
            if (data == null) {
                return null;
            }
            if (key == null || "".equals(key)) {
                throw new RuntimeException("AES加密时，密钥为空");
            }

            Cipher cipher = Cipher.getInstance(INSTANCE_KEY);
            /*// AES/CBC/PKCS5Padding 算法模式为CBC可以增加偏移量，可增加加密算法强度*/
            cipher.init(Cipher.ENCRYPT_MODE, getKeySpec(key),getIvSpec(key));
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("AES加密出错...",e);
        }
    }
    public static String encrypt2String(byte[] data,String key){
        byte[] encrypt = encrypt(data, key);
        String s = Base64.getEncoder().encodeToString(encrypt);
        return s;
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
            //String decode = URLDecoder.decode(content, CHARSET_NAME);
            //Base64.getDecoder().decode(decode);

            return decrypt2String(Base64.getDecoder().decode(content),key);
            //UnsupportedEncodingException
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("AES解密时 转换字节数组出错...",e);
        }
    }

    public static byte[] decrypt(byte[] data,String key){
        try {
            if (data == null) {
                return null;
            }
            if (key == null || "".equals(key)) {
                throw new RuntimeException("AES解密 密钥为空");
            }
            Cipher cipher = Cipher.getInstance(INSTANCE_KEY);
            cipher.init(Cipher.DECRYPT_MODE, getKeySpec(key),getIvSpec(key));
            byte[] bytes = cipher.doFinal(data);
            return bytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AES解密出错...",e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("AES解密出错...",e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES解密出错...",e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("AES解密出错...",e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("AES解密出错...",e);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException("AES解密出错...",e);
        }

    }

    public static String decrypt2String(byte[] data,String key){
        try {
            
            return new String(decrypt(data, key),CHARSET_NAME);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("AES解密后 转换字符串出错...",e);
        }
    }

    public static SecretKeySpec getKeySpec(String key){
        SecretKeySpec aes = new SecretKeySpec(key.getBytes(), "AES");
        return aes;
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


    public static String initKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            /***AES 要求密钥长度是128,192或者256位，由于JDK只支持128位的密钥所以当前采用128位的*/
            kg.init(128);
            SecretKey secretKey = kg.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
            //return byte2hex(secretKey.getEncoded());
            // return binary(secretKey.getEncoded(),16);
        } catch (Exception e) {
            throw new RuntimeException("AES密钥生成失败,请您重试",e);
        }
    }

    /**
     * 方法作用：将byte[]转为各种进制的字符串
     * @param bytes
     * @param radix
     * @return: java.lang.String
     * @createDate:  2019/12/30 11:08
     * @createAuthor: chenlin
     * @updateDate:  2019/12/30 11:08
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String binary(byte[] bytes, int radix) {
        // 这里的1代表正数
        return new BigInteger(1, bytes).toString(radix);
    }
    public static String byte2hex(byte[] b) {
        StringBuffer sb = new StringBuffer(b.length * 2);
        String tmp = "";
        for (int n = 0; n < b.length; n++) {
            tmp = (Integer.toHexString(b[n] & 0XFF));
            if (tmp.length() == 1) {
                sb.append("0");
            }
            sb.append(tmp);
        }
        return sb.toString().toUpperCase().substring(0, 16);
    }


    public static void main(String[] args) throws Exception {
        System.out.println("E5tuaUh2DpafAxQqy927HSh4sJlP2pZdEbBiju83QD6XFmtqLJpqh10LrYOujsT9hm43zWNel9TT3GaOrgX9dD9sjwf0d3peI4LzfpJ6jmQ=".length());
        String key = initKey();
        System.out.println(key+"  ====>;size="+key.length());
        /*String kk = key.substring(0,16);
        System.out.println("kk ="+ kk+" ===>"+kk.length());
        byte[] kkByte = kk.getBytes();
        for (byte b : kkByte) {
            System.out.println(b);
        }
        System.out.println("size : "+kkByte.length);*/
        String content = "{\"name\":\" !#%$^&*()唐氏综合征[{先天愚型}]```<.?;'< = @/ \"}";
        String encrypt = encrypt(content,key);
        System.out.println(content+" || 加密后为 ===> "+encrypt);

        String decrypt = decrypt(encrypt, key);

        System.out.println(content+" || 加密后为 ===> "+encrypt+" || 重新解密后===>"+decrypt);

        System.out.println("============");
        /*String str = "Ø";
        System.out.println("正确的字符串:"+str+","+Arrays.toString(str.getBytes()));
        *//*模拟数据库把编码变成gbk*//*
        byte[] chars = str.getBytes("gb2312");
        System.out.println(Arrays.toString(chars));
        String encodeStr = new String(chars,"gb2312");
        System.out.println("GBK:"+encodeStr);
        *//*把GBK编码转化成utf-8*//*
        System.out.println(new String(chars,"utf-8"));
        System.out.println("UTF:"+new String(encodeStr.getBytes(),"utf-8"));
        System.out.println("============");
        System.out.println(str.getBytes().length);
        System.out.println(str.getBytes("utf-8").length);
        System.out.println(str.getBytes("Unicode").length);
        System.out.println(str.getBytes("GBK").length);
        System.out.println("当前JRE：" + System.getProperty("java.version"));
        System.out.println("当前JVM的默认字符集：" + Charset.defaultCharset());

        byte[] b = new byte[]{-61, -104};
        System.out.println(new String(b));*/



    }

}
