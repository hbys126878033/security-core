package com.wondersgroup.security.controller.dto;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author chenlin
 * @create 2020-01-20 11:23
 * @description: TODO
 * @version：1.0
 **/
@Data
@Accessors(chain = true)
public class User {
    private String name;
    private String sex;
    private String age;
}
