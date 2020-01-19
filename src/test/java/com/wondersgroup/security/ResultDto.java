package com.wondersgroup.security;

import lombok.Data;

/**
 * @author chenlin
 * @create 2019-12-27 16:33
 * @description: TODO
 * @version：1.0
 **/
@Data
public class ResultDto {

    private String success;
    private String msg;


}
@Data
class Msg{
    private String success;
    private String message;
}