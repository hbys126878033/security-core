package com.wondersgroup.security.xss;

import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.HtmlUtils;

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


    @Test
    public void test02(){
        String value =  "百度";
        System.out.println(StringEscapeUtils.escapeHtml4(HtmlUtils.htmlEscape(value)));
        System.out.println(org.apache.commons.lang.StringEscapeUtils.escapeHtml("陈林"));
        System.out.println(HtmlUtils.htmlEscape("陈林"));
        System.out.println(StringEscapeUtils.escapeHtml4("陈林"));
    }
}
