package com.wondersgroup.security.controller;

import com.wondersgroup.security.crypto.annotation.EncryptAndDecrypt;
import com.wondersgroup.security.crypto.message.InputDto;
import com.wondersgroup.security.crypto.message.OutPutDto;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author chenlin
 * @create 2020-01-19 10:06
 * @description: TODO
 * @version：1.0
 **/
@Controller
@Slf4j
public class UserController {


    @RequestMapping(value = "/user",method = RequestMethod.GET)
    public String addUser(){
        return "user";
    }

    @RequestMapping(value="/user",method= RequestMethod.POST)
    @ResponseBody
    @EncryptAndDecrypt
    public OutPutDto addUser(@RequestBody User user){
        log.info(user.toString());
        OutPutDto result = new OutPutDto().setSuccess(true);
        return result.setData(user).setMessage("后台处理成功");
    }

}

@Data
class User {
    private String name;
    private String sex;
    private String age;
}
