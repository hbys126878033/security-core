package com.wondersgroup.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wondersgroup.security.crypto.core.AesUtils;
import com.wondersgroup.security.crypto.core.RsaUtils;
import com.wondersgroup.security.dto.RsaDto;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.math.BigInteger;
import java.nio.charset.Charset;

@SpringBootTest
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
class SecurityCoreApplicationTests {


    @Autowired
    private MockMvc mockMvc;

    @Test
    void contextLoads() {
        //RsaUtils.generateKeyPair();
    }

    @Test
    public void encrypt(){
        try {
            MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/getPublicKey")).andReturn();
            String contentAsString = mvcResult.getResponse().getContentAsString();
            System.out.println("result : \n"+contentAsString);

            ObjectMapper mapper = new ObjectMapper();
            RsaDto rsaDto = mapper.readValue(contentAsString, RsaDto.class);
            System.out.println("RSADTO :r \n"+ rsaDto);

            BCRSAPublicKey publicKey = RsaUtils.getPublicKey(new BigInteger(rsaDto.getPublicModulus(),16), new BigInteger(rsaDto.getPublicExponent(),16));
            AsymmetricKeyParameter publicKeyParameter = RsaUtils.getPublicKeyParameter(publicKey);
            String cipher = "chen林";
            String data = RsaUtils.encrypt4Base64(cipher, publicKeyParameter);
            MvcResult mvcResult1 = mockMvc.perform(
                    MockMvcRequestBuilders.post("/postEncryptData")
                            .param("data", data)
                            .param("chiper", cipher)
                            .param("_flag", "2"))
                    .andReturn();

            String contentAsString1 = mvcResult1.getResponse().getContentAsString();
            System.out.println("加密返回值："+contentAsString1);
            ResultDto resultDto = mapper.readValue(contentAsString1, ResultDto.class);
            System.out.println("result Dto ：\n"+resultDto);

            String decrypt4Base64 = RsaUtils.decrypt4Base64(resultDto.getMsg(), publicKeyParameter);
            System.out.println("decrypt4Base64 = "+ decrypt4Base64);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testAes(){
        try {
            String data = "<p><span style=\"font-size: 22px;\"><strong><span style=\"font-family: Tahoma; background-color: rgb(255, 255, 255);\">请各个区及时下发最新接口规范，并通知各已经完成明细数据生成或正在调试上传明细的医院于9月底完成明细文件里物价编码信息增补的修改，并于2019.9.30我们更新系统后及时更新版本，以免影响明细比对[13123]。</span></strong></span></p>";

            String key = AesUtils.initKey();

            String encrypt = AesUtils.encrypt(data,key);

            MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/aesTest")
                    .param("data", data)
                    .param("encrypt", encrypt)
                    .param("key", key).param("_flag", "1")).andReturn();
            String contentAsString = mvcResult.getResponse().getContentAsString(Charset.forName("utf-8"));
            System.out.println(contentAsString);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
