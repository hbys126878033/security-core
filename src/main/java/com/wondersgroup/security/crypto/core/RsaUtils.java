package com.wondersgroup.security.crypto.core;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

/**
 * @author chenlin
 * @create 2019-12-27 10:04
 * @description: 基于bouncycastle的RSA算法实现帮助类
 * @version：1.0
 **/
public class RsaUtils {

    private static BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

    /**
     * 初始化时配置的密钥长度
     **/
    public static final int KEY_SIZE = 1024;

    /**
     * 临时保存密钥对
     **/
    public static KeyPair KEY_PAIR = null;

    /**
     * base64 编码器
     */
    public static final Encoder ENCODER =  Base64.getEncoder();

    /**
     * base64 解码器
     */
    public static final Decoder DECODER = Base64.getDecoder();

    public static final String UTF_8 = "utf-8";

    private RsaUtils(){
    }

    /**
     * 方法作用：根据bouncyCastleProvider 生成密钥对
     * @param
     * @return: java.security.KeyPair
     * @createDate:  2019/12/27 10:17
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 10:17
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static KeyPair generateKeyPair(){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", bouncyCastleProvider);

            keyPairGen.initialize(KEY_SIZE, new SecureRandom());
            KeyPair keyPair = keyPairGen.generateKeyPair();
            KEY_PAIR = keyPair;
            //class org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
            //class org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
            return keyPair;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("RSA 密钥对初始化失败 ...",e);
        }
    }


    /**
     * 方法作用：通过base64传输 的加密算法
     * @param data
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 15:04
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 15:04
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String encrypt4Base64(String data,AsymmetricKeyParameter key){
        try {
            byte[] encodeBytes = data.getBytes("utf-8");
            byte[] bytes = encrypt(encodeBytes,key);
            return ENCODER.encodeToString(bytes);
        } catch (Exception  e) {
            throw new RuntimeException("RSA 加密失败",e);
        }
    }

    /**
     * 方法作用：为javascript用 的加密算法
     * @param data
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 15:03
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 15:03
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String encrypt4Javascript(String data,AsymmetricKeyParameter key) {
        try {
            /* URLEncoder.encode 处理中文的问题，*/
            byte[] encodeBytes = URLEncoder.encode(data,UTF_8).getBytes(UTF_8);
            Base64.getUrlEncoder().encodeToString(encodeBytes);
            byte[] bytes = encrypt(encodeBytes,key);
            return byteToString(bytes);
        } catch (Exception e) {
            throw new RuntimeException("RSA 加密失败",e);
        }
    }

    /**
     * 方法作用：加密算法
     * @param data
     * @param key
     * @return: byte[]
     * @createDate:  2019/12/27 15:03
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 15:03
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static byte[] encrypt(byte[] data,AsymmetricKeyParameter key) {
        try {
            if (data == null) {
                return null;
            }
            /* 创建加解密对象*/
            AsymmetricBlockCipher cipher = new RSAEngine();
            cipher.init(true,key);
            return cipher.processBlock(data, 0, data.length);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("RSA 加密失败",e);
        }
    }



    /**
     * 方法作用：解密方法，返回utf-8编码的字符串
     * @param data
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 14:40
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:40
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String decrypt2String(byte[] data,AsymmetricKeyParameter key) {
        try {
            return new String(decrypt(data,key),"utf-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException("RSA 解密加密失败",e);
        }
    }

    /**
     * 方法作用：解密方法，返回字节数组
     * @param data
     * @param key
     * @return: byte[]
     * @createDate:  2019/12/27 14:41
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:41
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static byte[] decrypt(byte[] data,AsymmetricKeyParameter key){
        try {
            if (data == null) {
                return null;
            }
            AsymmetricBlockCipher cipher = new RSAEngine();
            cipher.init(false,key);
            return cipher.processBlock(data, 0, data.length);
        } catch (Exception e) {
            throw new RuntimeException("RSA 解密失败",e);
        }
    }

    /**
     * 方法作用：解密前段通过javascript加密的数据，
     * @param data
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 14:42
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:42
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String decryptFromJavascript(String data,AsymmetricKeyParameter key) {
        try {
            /**
             *  先处理中文问题
             * 由于javascript加密后字符串太长，需要通过把字符串转成16进制，然后解密，最后倒序
             * */
            byte[] decodeData = hexStringToBytes(URLDecoder.decode(data,UTF_8));
            String decrypt = decrypt2String(decodeData, key);
            StringBuilder sb = new StringBuilder(decrypt).reverse();
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("RSA 解密失败",e);
        }
    }

    /**
     * 方法作用：解密 先用rsa加密，然后通过base64编码的数据
     * @param data
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 14:46
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:46
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String decrypt4Base64(String data,AsymmetricKeyParameter key){
        byte[] decode = DECODER.decode(data);
        return decrypt2String(decode,key);
    }

    /**
     * 方法作用：获取公钥对象
     * @param
     * @return: org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
     * @createDate:  2019/12/27 10:17
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 10:17
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static BCRSAPublicKey getPublicKey(){
        if(KEY_PAIR == null){
            return null;
        }
        return (BCRSAPublicKey)KEY_PAIR.getPublic();
    }

    /**
     * 方法作用：获取私钥对象
     * @param
     * @return: org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
     * @createDate:  2019/12/27 10:18
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 10:18
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static BCRSAPrivateCrtKey getPrivateKey(){
        if(KEY_PAIR == null){
            return null;
        }

        return (BCRSAPrivateCrtKey)KEY_PAIR.getPrivate();
    }

    /**
     * 方法作用：获取公钥字符串对象
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 10:24
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 10:24
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String getPublicKey(BCRSAPublicKey key){
        if(key != null){
            return ENCODER.encodeToString(key.getEncoded());
        }else{
            throw new RuntimeException("公钥对象为空，不能转成字符串");
        }
    }

    /**
     * 方法作用：
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 10:27
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 10:27
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String getPrivateKey(BCRSAPrivateCrtKey key){
        if (key != null) {
            return ENCODER.encodeToString(key.getEncoded());
        } else {
            throw new RuntimeException("私钥对象为空，不能转成字符串");
        }
    }

    /**
     * 方法作用：把公钥字符串转换成公钥对象
     * @param key
     * @return: org.bouncycastle.crypto.params.AsymmetricKeyParameter
     * @createDate:  2019/12/27 11:10
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:10
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static AsymmetricKeyParameter getPublicKeyParameter(BCRSAPublicKey key){
        try {
            return getPublicKeyParameter(getPublicKey(key));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("RAS 把公钥字符串转换成公钥对象失败 ");
        }
    }
    /**
     * 方法作用：把公钥字符串转换成公钥对象
     * @param key
     * @return: org.bouncycastle.crypto.params.AsymmetricKeyParameter
     * @createDate:  2019/12/27 16:25
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 16:25
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static AsymmetricKeyParameter getPublicKeyParameter(String key) {
        try {
            /* 通过base64解码把密钥字符串转化成字节数组 */
            byte[] publicKeys = DECODER.decode(key);
            //ASN1Object pubKeyObj = ASN1Primitive.fromByteArray(publicKeys);
            //SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pubKeyObj);
            AsymmetricKeyParameter key1 = PublicKeyFactory.createKey(publicKeys);
            return key1;
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("RAS 把公钥字符串转换成公钥对象失败 ");
        }
    }


    /**
     * 方法作用：把私钥字符串转换成公钥对象
     * @param key
     * @return: org.bouncycastle.crypto.params.AsymmetricKeyParameter
     * @createDate:  2019/12/27 11:05
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:05
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static AsymmetricKeyParameter getPrivateKeyParameter(String key) {
        try {
            byte[] decode = DECODER.decode(key);
            AsymmetricKeyParameter key1 = PrivateKeyFactory.createKey(decode);
            return key1;
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("RAS 把私钥字符串转换成公钥对象失败 ");
        }
    }

    /**
     * 方法作用：把私钥字符串转换成公钥对象
     * @param key
     * @return: org.bouncycastle.crypto.params.AsymmetricKeyParameter
     * @createDate:  2019/12/27 16:26
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 16:26
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static AsymmetricKeyParameter getPrivateKeyParameter(BCRSAPrivateCrtKey key) {
        return getPrivateKeyParameter(getPrivateKey(key));
    }

    /**
     * 方法作用：根据模和指数转换成公钥
     * @param publicModulus
     * @param publicExponent
     * @return: org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
     * @createDate:  2019/12/27 11:22
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:22
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static BCRSAPublicKey getPublicKey(String publicModulus,String publicExponent) {
        try {
            return getPublicKey(new BigInteger(publicModulus),new BigInteger(publicExponent));
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("RAS 根据模和指数转换成公钥对象失败 ");
        }
    }

    /**
     * 方法作用：根据模和指数转换成公钥
     * @param publicModulus
     * @param publicExponent
     * @return: org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
     * @createDate:  2019/12/27 11:22
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:22
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static BCRSAPublicKey getPublicKey(BigInteger publicModulus,BigInteger publicExponent) {
        try {
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(publicModulus, publicExponent);
            BCRSAPublicKey rsa = (BCRSAPublicKey)KeyFactory.getInstance("RSA",bouncyCastleProvider).generatePublic(rsaPublicKeySpec);
            return rsa;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("RAS 根据模和指数转换成公钥对象失败 ");
        }
    }


    /**
     * 方法作用： 根据私钥信息和公钥的指数生成私钥
     * @param privateModulus
     * @param publicExponent
     * @param privateExponent
     * @param primeP
     * @param primeQ
     * @param primeExponentP
     * @param primeExponentQ
     * @param crtCoefficient
     * @return: org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
     * @createDate:  2019/12/27 11:30
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:30
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static BCRSAPrivateCrtKey getPrivateKey(BigInteger privateModulus,
                                                   BigInteger publicExponent,
                                                   BigInteger privateExponent,
                                                   BigInteger primeP,
                                                   BigInteger primeQ,
                                                   BigInteger primeExponentP,
                                                   BigInteger primeExponentQ,
                                                   BigInteger crtCoefficient) {
        try {
            RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = new RSAPrivateCrtKeySpec(
                    privateModulus,
                    publicExponent,
                    privateExponent,
                    primeP,
                    primeQ,
                    primeExponentP,
                    primeExponentQ,
                    crtCoefficient);

            return (BCRSAPrivateCrtKey)KeyFactory.getInstance("RSA",bouncyCastleProvider).generatePrivate(rsaPrivateCrtKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("RAS 根据模和指数等信息转换成私钥对象失败 ");
        }
    }

    /**
     * 方法作用：根据私钥信息和公钥的指数生成私钥
     * @param privateModulus
     * @param publicExponent
     * @param privateExponent
     * @param primeP
     * @param primeQ
     * @param primeExponentP
     * @param primeExponentQ
     * @param crtCoefficient
     * @return: org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
     * @createDate:  2019/12/27 11:34
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:34
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static BCRSAPrivateCrtKey getPrivateKey(String privateModulus,
                                                   String publicExponent,
                                                   String privateExponent,
                                                   String primeP,
                                                   String primeQ,
                                                   String primeExponentP,
                                                   String primeExponentQ,
                                                   String crtCoefficient) {
        return getPrivateKey(new BigInteger(privateModulus),
                             new BigInteger(publicExponent),
                             new BigInteger(privateExponent),
                             new BigInteger(primeP),
                             new BigInteger(primeQ),
                             new BigInteger(primeExponentP),
                             new BigInteger(primeExponentQ),
                             new BigInteger(crtCoefficient));
    }


    /**
     * 方法作用：把字节数组的密钥转换成字符串类型的密钥
     * @param key
     * @return: java.lang.String
     * @createDate:  2019/12/27 11:24
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 11:24
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static String encodeKey2String(byte[] key){
        return ENCODER.encodeToString(key);
    }

    /**
     * 方法作用：把字符串转换成16进制的字节数组
     * @param hexString
     * @return: byte[]
     * @createDate:  2019/12/27 14:52
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:52
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    public static byte[] hexStringToBytes(String hexString){
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    /**
     * 方法作用：把字符转换成16进制的byte
     * @param c
     * @return: byte
     * @createDate:  2019/12/27 14:53
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:53
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    /**
     * 方法作用：把byte数组转换成16进制的字符串
     * @param bytes
     * @return: java.lang.String
     * @createDate:  2019/12/27 14:55
     * @createAuthor: chenlin
     * @updateDate:  2019/12/27 14:55
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    private static String byteToString(byte[] bytes) {
        int length = bytes.length;
        StringBuffer buf = new StringBuffer(length);
        for (int i = 0; i < length; i++) {
            int d = bytes[i];
            if (d < 0) {
                d += 256;
            }
            if (d < 16) {
                buf.append("0");
            }
            buf.append(Integer.toString(d, 16));
        }
        return buf.toString();
    }


    public static void main(String[] args) {
        generateKeyPair();
        BCRSAPublicKey publicKey = getPublicKey();
        BCRSAPrivateCrtKey privateKey = getPrivateKey();

        String privateK = encodeKey2String(privateKey.getEncoded());
        String publicK = encodeKey2String(publicKey.getEncoded());

        String data = "chenlin$=%+[)}@!#%^";
        String encrypt = encrypt4Base64(data,getPublicKeyParameter(publicK));
        String decrypt = decrypt4Base64(encrypt,getPrivateKeyParameter(privateK));
        System.out.println("明文信息:\n"+data);
        System.out.println("加密信息:\n"+encrypt);
        System.out.println("解密信息:\n"+decrypt);
        System.out.println("加解密后是否一致:"+(data.equals(decrypt)));
       /* BCRSAPublicKey publicKey1 = getPublicKey(publicKey.getModulus().toString(), publicKey.getPublicExponent().toString());
        BCRSAPrivateCrtKey privateKey1 = getPrivateKey(privateKey.getModulus(), publicKey.getPublicExponent(), privateKey.getPrivateExponent(), privateKey.getPrimeP(), privateKey.getPrimeQ(), privateKey.getPrimeExponentP(), privateKey.getPrimeExponentQ(), privateKey.getCrtCoefficient());

        System.out.println("public 是否可以还原:"+(encodeKey2String(publicKey.getEncoded()).equals(encodeKey2String(publicKey1.getEncoded()))));
        System.out.println("private 是否可以还原:"+(encodeKey2String(privateKey.getEncoded()).equals(encodeKey2String(privateKey1.getEncoded()))));
        */


    }
}
