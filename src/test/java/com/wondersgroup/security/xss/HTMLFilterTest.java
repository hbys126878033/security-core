package com.wondersgroup.security.xss;

import org.junit.Before;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author chenlin
 * @create 2020-01-16 21:16
 * @description: TODO
 * @version：1.0
 **/
public class HTMLFilterTest {

    private HTMLFilter htmlFilter ;

    @BeforeEach
    public void setUp(){
        System.out.println("init");
        this.htmlFilter = new HTMLFilter();
    }
    @Test
    public void test01(){
        String content = "<a href='http://www.baidu.com'> link to 百度 <> | % & \' \" _</a>";
        System.out.println(content);
        System.out.println(htmlFilter);
        System.out.println(this.htmlFilter.filter(content));
    }
}
