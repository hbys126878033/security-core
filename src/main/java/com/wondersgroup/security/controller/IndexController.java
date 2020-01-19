package com.wondersgroup.security.controller;
import com.wondersgroup.security.crypto.annotation.EncryptAndDecrypt;
import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RSAUtilsOld;
import com.wondersgroup.security.crypto.core.RsaUtils;
import com.wondersgroup.security.crypto.message.OutPutDto;
import com.wondersgroup.security.dto.AesDto;
import com.wondersgroup.security.dto.RsaAndAesDto;
import com.wondersgroup.security.dto.RsaDto;
import com.wondersgroup.security.dto.UserDto;
import com.wondersgroup.security.intercepter.Crypto;
import com.wondersgroup.security.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.util.Base64;

/**
 * @author chenlin
 * @create 2019-12-26 14:21
 * @description:
 *          https://blog.csdn.net/huialfred/article/details/79331271
 * @version：1.0
 **/
@Controller
@Slf4j
public class IndexController implements InitializingBean {

    @RequestMapping(value={"/","index"})
    public String index(){
        return "index";
    }

    @RequestMapping(value="/rsaEncryptPage")
    public String rsaEncryptPage(Model model){
        //model.addAttribute("m",RSAUtils.getModulus());
        //model.addAttribute("e",RSAUtils.getPublicExponent());
        //model.addAttribute("key",RSAUtils.getPublicKey());
        return "rsaEncrypt";
    }

    @RequestMapping(value="/getPublicKey")
    @ResponseBody
    public RsaDto getPublicKey(){
        BCRSAPublicKey publicKey = RsaUtils.getPublicKey();
        RsaDto dto = new RsaDto().setPublicModulus(publicKey.getModulus().toString(16)).setPublicExponent(publicKey.getPublicExponent().toString(16));
        //RsaDto dto = new RsaDto().setPublicKey(RSAUtilsOld.getPublicKey()).setPublicModulus(RSAUtilsOld.getModulus()).setPublicExponent(RSAUtilsOld.getPublicExponent());
        System.out.println(dto);
        return dto;
    }

    @RequestMapping(value="/postEncryptData")
    @ResponseBody
    public String postEncryptData(String data,String chiper,String _flag) throws Exception {
        StringBuilder result = new StringBuilder(20);
        BCRSAPrivateCrtKey privateKey = RsaUtils.getPrivateKey();
        AsymmetricKeyParameter keyParameter = RsaUtils.getPrivateKeyParameter(RsaUtils.encodeKey2String(privateKey.getEncoded()));
        try {


            //String decrypt = RSAUtilsOld.decryptPrivate(data);
            //data = RsaUtils.hexStringToBytes(data);
            String decrypt = null;
            if ("1".equals(_flag)) {
                decrypt = RsaUtils.decryptFromJavascript(data,keyParameter);
            } else  {
                decrypt = RsaUtils.decrypt4Base64(data,keyParameter);
            }
            System.out.println("解密后："+decrypt);
            System.out.println("明文信息:"+chiper);

            boolean b = chiper.equals(decrypt);
            System.out.println("是否一致:"+b);

            if (b) {
                result.append("{\"success\":true,\"message\":\"后台解密成功\"}");
            } else {
                result.append("{\"success\":true,\"message\":\"后台解密失败\"}");
            }

        } catch (Exception e) {
            e.printStackTrace();
            result.append("{\"success\":true,\"message\":\"后台解密失败\"}");
        }
        System.out.println("返回值:"+result.toString());
        String s = null;
        if ("1".equals(_flag)) {
            s = RsaUtils.encrypt4Javascript(result.toString(), keyParameter);
        } else {
            s = RsaUtils.encrypt4Base64(result.toString(), keyParameter);
        }
        System.out.println("返回值密文:"+s);
        return  "{\"success\":true,\"msg\":\""+s+"\"}";
    }


    @RequestMapping(value="aes",method= RequestMethod.GET)
    public String aes(){
        return "aes";
    }

    @RequestMapping(value="aesTest")
    @ResponseBody
    public AesDto aesTest(String data,String encrypt,String key,String _flag){
        log.info("data = {},encrypt={},key={},Key_z=size = {},_flag = {}",data,encrypt,key,key.length(),_flag);
        AesDto aesDto = new AesDto();
        String message = "";
        try {
            String decrypt = AesUtils.decrypt(encrypt, key);
            aesDto.setDecrypt(decrypt);
            if (decrypt.equals(data)) {
                message = "java 成功解密 " ;
            }else{
                message = "java 解密失败 " ;
            }
        } catch (Exception e) {
            e.printStackTrace();
            message = "java 解密报错 " ;
        }
        aesDto.setMessage(message);
        aesDto.setKey(AesUtils.initKey());
        aesDto.setEncrypt(AesUtils.encrypt(aesDto.getMessage(),aesDto.getKey()));
        return aesDto;
    }


    @RequestMapping(value="/rsa_aes",method = RequestMethod.GET)
    public String rsa_aes(){
        return "rsa_aes";
    }

    @RequestMapping(value="/rsa_aes",method=RequestMethod.POST)
    @ResponseBody
    @Crypto
    public RsaAndAesDto rsaAes(RsaAndAesDto dto, String telphone, HttpServletRequest request){
        log.info(" Telphone = {}",telphone);
        dto.set_flag(request.getParameter("_flag"));
        dto.set_encryptData(request.getParameter("_encryptData"));
        dto.set_key(request.getParameter("_key"));
        log.info("_flag = {}",dto.get_flag());

        BCRSAPrivateCrtKey privateKey = RsaUtils.getPrivateKey();
        AsymmetricKeyParameter keyParameter = RsaUtils.getPrivateKeyParameter(RsaUtils.encodeKey2String(privateKey.getEncoded()));
        RsaAndAesDto returnDto = new RsaAndAesDto();
        String result = null;
        try {
            String aesKey = null;
            if ("1".equals(dto.get_flag())) {
                aesKey = RsaUtils.decryptFromJavascript(dto.get_key(),keyParameter);
            } else  {
                aesKey = RsaUtils.decrypt4Base64(dto.get_key(),keyParameter);
            }

            log.info("_aesKey = {}",aesKey);
            String data = AesUtils.decrypt(dto.get_encryptData(),aesKey);
            log.info("encryptData = {}",data);
            result = "ras aes [] ''+= 加解密测试成功";
            returnDto.setSuccess(true);
        } catch (Exception e) {
            e.printStackTrace();
            result = "ras aes [] ''+= 加解密测试失败";
            returnDto.setSuccess(false);
        }
        String aesKey = AesUtils.initKey();
        returnDto.set_encryptData(AesUtils.encrypt(result,aesKey));
        if ("1".equals(dto.get_flag())) {
            returnDto.set_key(RsaUtils.encrypt4Javascript(aesKey, keyParameter));
        } else {
            returnDto.set_key(RsaUtils.encrypt4Base64(aesKey, keyParameter));
        }
        System.out.println(returnDto);
        return returnDto;
    }



    @RequestMapping(value="/rsa_aes_interceptor",method = RequestMethod.GET)
    public String rsa_aes_interceptor(){
        return "rsa_aes_interceptor";
    }

    @RequestMapping(value="/rsa_aesInterceptor",method=RequestMethod.POST)
    @ResponseBody
    @EncryptAndDecrypt
    public OutPutDto rsaAesInterceptor(String decrypt, String telphone, String _flag){
        log.info("telphone = {}",telphone);
        log.info("encrypt = {} ",decrypt);
        UserDto userDto = JsonUtil.decode(decrypt, UserDto.class);
        System.out.println(userDto);
        //return new OutPutDto().setSuccess(true).setData("rsa aes 通过filter自动解密成功").setFlag(_flag);
        return new OutPutDto().setSuccess(true).setData(userDto).setFlag(_flag);
    }


    @Override
    public void afterPropertiesSet() throws Exception {

        RsaUtils.generateKeyPair();
        RSAUtilsOld.generateKeyPair();
        KeyPair keyPair = RSAUtilsOld.KEY_PAIR;
        BCRSAPublicKey aPublic = (BCRSAPublicKey)keyPair.getPublic();
        String publicKeyString1 = Base64.getEncoder().encodeToString(aPublic.getEncoded());
        System.out.println("RSA 公钥 index:\n"+publicKeyString1);

        BCRSAPrivateCrtKey aPrivate = (BCRSAPrivateCrtKey) keyPair.getPrivate();
        String privateKeyString1 = Base64.getEncoder().encodeToString(aPrivate.getEncoded());
        System.out.println("RSA 私钥 index:\n"+ privateKeyString1);


    }
}
