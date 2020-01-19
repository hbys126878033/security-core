package com.wondersgroup.security.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Writer;
import java.net.URLDecoder;
import java.time.LocalDateTime;

/**
 * @author chenlin
 * @create 2020-01-03 9:16
 * @description: 文件上传
 * @version：1.0
 **/
@Controller
@Slf4j
public class UploadController {

    @RequestMapping(value="/web_upload",method= RequestMethod.GET)
    public String webUpload(){
        return "web_upload";
    }

    @RequestMapping(value="/web_upload_second",method= RequestMethod.GET)
    public String web_upload_second(){
        return "web_upload_second";
    }

    @RequestMapping(value="/web_upload_three",method= RequestMethod.GET)
    public String web_upload_three(){
        return "web_upload_three";
    }

    @RequestMapping(value="/upload",method = RequestMethod.POST)
    public void uploadFiles(@RequestParam("file") MultipartFile[] files, HttpServletResponse response) throws IOException {
        System.out.println(files.length);
        System.out.println("您在上传文件:"+ LocalDateTime.now().toString());
        response.setContentType("text/html;charset=utf-8");
        Writer writer = response.getWriter();
        writer.write("{\"success\":true}");
        writer.flush();
    }


	@RequestMapping(value="/download/yhsc")
	public ResponseEntity<byte[]> yhsc(HttpSession session) throws IOException{
		byte [] body = null;
		/*ServletContext servletContext = session.getServletContext();
		InputStream in = servletContext.getResourceAsStream("/resource/doc/yhsc.docx");
		body = new byte[in.available()];
		in.read(body);*/
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Disposition", "attachment;filename="+java.net.URLEncoder.encode("上海市少儿住院互助基金管理系统用户手册"+".docx","UTF-8"));
		HttpStatus statusCode = HttpStatus.OK;
		ResponseEntity<byte[]> response = new ResponseEntity<byte[]>(body, headers, statusCode);
		return response;
	}

    @RequestMapping(value="/prviewImag")
    @ResponseBody
    public ResponseEntity<Resource>  previewImage(String yxwz) throws IOException {
        yxwz = URLDecoder.decode(yxwz,"UTF-8");
        String path="" ;
        final File directory = new File(path);
        File file = new File(directory+File.separator+yxwz);
        if(!file.exists()){
            throw new RuntimeException("message");
        }
        FileInputStream fis = new FileInputStream(file);
        InputStreamResource resource = new InputStreamResource(fis);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE,"image/*");
        headers.add(HttpHeaders.CONTENT_LENGTH,Integer.valueOf(fis.available()).toString());
        return new ResponseEntity<Resource>(resource,headers, HttpStatus.OK);
    }
}
