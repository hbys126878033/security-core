package com.wondersgroup.security.crypto.filter;

import org.apache.commons.lang.StringEscapeUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.*;
import java.util.Map.Entry;

/**
 * @author chenlin
 * @create 2020-01-02 9:09
 * @description: reqeust对象的包装器，使用该对象后，会用本类的对象替换原来的reqeust对象，
 * @version：1.0
 **/
public class DecryptRequestWrapper extends HttpServletRequestWrapper {

    /**原始的request对象*/
    private HttpServletRequest origRequest;

    /** 储存参数的键值对 */
    private Map<String,String[]> params;

    /** 是否开启XSS攻击的过滤功能*/
    private Boolean enabledXss;

    private Set<String> skipProperties;

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request The request to wrap
     * @throws IllegalArgumentException if the request is null
     */
    public DecryptRequestWrapper(HttpServletRequest request,Map<String,String[]> params,Boolean enabledXss) {
        super(request);
        this.origRequest = request;
        this.enabledXss = enabledXss;
        if (this.enabledXss) {
            xssFilter(params);
        } else {
            this.params = params;
        }
        handlerOriginalParameters(request);

        skipProperties = new HashSet<String>();
        skipProperties.add("dh");
    }


    /**
     * 方法作用：xss 过滤
     * @param params
     * @return: void
     * @createDate:  2020/1/20 9:31
     * @createAuthor: chenlin
     * @updateDate:  2020/1/20 9:31
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    private void xssFilter(Map<String,String[]> params){
        this.params = new HashMap<String,String[]>(params.size());
        for (Entry<String, String[]> entry : params.entrySet()) {
            System.out.println(entry.getKey());
            System.out.println(entry.getValue());
            this.params.put(entry.getKey(),xssEncode(entry.getValue()));
        }
    }

    /**
     * 方法作用：XSS 过滤
     * @param value
     * @return: java.lang.String[]
     * @createDate:  2020/1/20 9:32
     * @createAuthor: chenlin
     * @updateDate:  2020/1/20 9:32
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    private String[] xssEncode(String[] value){
        if (StringUtils.isEmpty(value)) {
            return value;
        }
        for (int i = 0,length = value.length; i < length; i++) {
            System.out.println(value[i]);
            value[i] = xssEncode(value[i]);
        }
        return value;
    }

    /**
     * 方法作用：XSS过滤
     * @param value
     * @return: java.lang.String
     * @createDate:  2020/1/20 9:32
     * @createAuthor: chenlin
     * @updateDate:  2020/1/20 9:32
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    private String xssEncode(String value) {
        if (StringUtils.hasText(value)) {
            return value = StringEscapeUtils.escapeHtml(HtmlUtils.htmlEscape(value));
        }else{
            return value;
        }
    }

    /**
     * 方法作用：把原有的Request对象的参数，复制到当前对象的params中，后面直接从当前对象的params中直接获取参数
     * @param request
     * @return: void
     * @createDate:  2020/1/2 9:15
     * @createAuthor: chenlin
     * @updateDate:  2020/1/2 9:15
     * @updateAuthor:  修改作者
     * @updateRemark:  修改内容
     **/
    private void handlerOriginalParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        for (Entry<String, String[]> entry : parameterMap.entrySet()) {
            this.params.put(entry.getKey(),entry.getValue());
        }
    }

    @Override
    public String getParameter(String name) {
        String[] value = params.get(name);
        return value == null ? null : value[0];
    }

    @Override
    public String getHeader(String name) {
        String header = super.getHeader(name);
        if (this.enabledXss) {
            return xssEncode(header);
        }
        return header;
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        Enumeration<String> headers = super.getHeaders(name);
        if (this.enabledXss && headers != null) {
            List<String> result = new ArrayList<String>();
            while (headers.hasMoreElements()){
                result.add(xssEncode(headers.nextElement()));
            }
            return Collections.enumeration(result);
        }
        return headers;
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return super.getHeaderNames();
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return params;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(this.params.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return this.params.get(name);
    }

    public HttpServletRequest getOrigRequest() {
        return origRequest;
    }
}
