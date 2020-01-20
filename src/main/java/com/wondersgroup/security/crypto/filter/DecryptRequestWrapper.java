package com.wondersgroup.security.crypto.filter;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
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
@Slf4j
public class DecryptRequestWrapper extends HttpServletRequestWrapper {

    /**原始的request对象*/
    private HttpServletRequest origRequest;

    /** 储存参数的键值对 */
    private Map<String,String[]> params;

    /** 是否开启XSS攻击的过滤功能*/
    private Boolean enabledXss;

    /** 如果有字段需要取消XSS过滤，可以配置该集合中*/
    private Set<String> skipProperties;

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request The request to wrap
     * @throws IllegalArgumentException if the request is null
     */
    public DecryptRequestWrapper(HttpServletRequest request,Map<String,Object> data,Boolean enabledXss) {
        super(request);
        /**储存之前的reqeust*/
        this.origRequest = request;
        /**是否开启XSS过滤*/
        this.enabledXss = enabledXss;
        /** 初始化不需要XSS过滤的属性列表*/
        initSkipProperties();
        /** 初始化参数容器，容器大小是传过来的map的大小加上原始request域中参数Map的长度*/
        this.params = new HashMap<String,String[]>(data.size()+request.getParameterMap().size());
        /** 把传过来的Map对象的类型转换一下*/
        obj2StringArray(data);
        /** 处理未加密通道的数据 */
        handlerOriginalParameters(request);
    }


    private void initSkipProperties(){
        skipProperties = new HashSet<String>();
        /** 特殊处理，档号*/
        skipProperties.add("dh");
        /** _flag 加密相关*/
        skipProperties.add("_flag");
        /** _encryptData 加密相关*/
        skipProperties.add("_encryptData");
        /** _key 加密相关*/
        skipProperties.add("_key");
    }

    private void obj2StringArray(Map<String,Object> data){
        if (data != null && data.size() > 0) {
            String[] values;
            for (Entry<String, Object> entry : data.entrySet()) {
                Class clazz = entry.getValue().getClass();
                //TODO 这个地方暂时有点疑问，数组的参数和list参数未处理，
                if (clazz.getName().equals("java.lang.String")) {
                    if (enabledXss) {
                        values = new String[]{this.xssEncode((String)entry.getValue())} ;
                    }else{
                        values = new String[]{(String)entry.getValue()};
                    }
                } else {
                    if (enabledXss) {
                        values = new String[]{this.xssEncode(entry.getValue().toString())};
                    } else {
                        values = new String[]{entry.getValue().toString()};
                    }
                }
                this.params.put(entry.getKey(),values);
            }
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
            if (enabledXss) {
                this.params.put(entry.getKey(),xssEncode(entry.getValue())) ;
            } else {
                this.params.put(entry.getKey(),entry.getValue());
            }
        }
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
            this.params.put(entry.getKey(),this.xssEncode(entry.getValue()));
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
        if (StringUtils.hasText(value) && !skipProperties.contains(value) ) {
            value = StringEscapeUtils.escapeHtml4(HtmlUtils.htmlEscape(value));
            return value;
        }else{
            return value;
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
