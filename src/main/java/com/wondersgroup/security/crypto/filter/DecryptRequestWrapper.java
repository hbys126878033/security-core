package com.wondersgroup.security.crypto.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
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

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request The request to wrap
     * @throws IllegalArgumentException if the request is null
     */
    public DecryptRequestWrapper(HttpServletRequest request) {
        super(request);
        this.origRequest = request;
        this.params = params;
        handlerOriginalParameters(request);
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
