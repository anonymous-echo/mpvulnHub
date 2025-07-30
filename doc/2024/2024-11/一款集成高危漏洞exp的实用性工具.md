#  一款集成高危漏洞exp的实用性工具   
 黑白之道   2024-11-18 02:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
**01**  
  
**工具介绍**  
  
该工具使用了ExpDemo-JavaFX项目，保留了核心的数据包请求接口，使用jdk1.8环境开发。目前编写了oa、设备、框架、产品等多个系列，对相关漏洞进行复现和分析，极力避免exp的误报和有效性。  
  
  
截止到目前为止，已实现了用友、泛微、蓝凌、万户、帆软报表、致远、通达、红帆、金和、金蝶、广联达、华天动力总共12个OA。全部是命令执行、文件上传类的漏洞，包括前台和后台。  
  
  
用友已完成：  
- 用友NC-BshServlet 远程命令执行  
  
- 用友NC-BshServlet-bypass 远程命令执行  
  
- 用友NC accept 文件上传  
  
- 用友NC uapim 文件上传  
  
- 用友NC mp 文件上传  
  
- 用友NC saveXmlToFileServlet 文件上传  
  
- 用友NC FileManager 文件上传  
  
- 用友NC saveImageServlet 文件上传  
  
- 用友NC反序列化-1  
  
- 用友NC反序列化-2  
  
- 用友NC反序列化-3  
  
- 用友NC Cloud 文件写入  
  
- 用友NC Cloud uploadChunk文件上传  
  
- 用友NC Cloud importhttpscer文件上传  
  
- 用友U8CRM swfupload 文件上传  
  
- 用友U8CRM getemaildata 文件上传  
  
- 用友U8CRM crmtools 文件上传  
  
- 用友GRP-U8 UploadFileData 文件上传  
  
- 用友GRP-U8 U8AppProxy 文件上传  
  
- 用友GRP-U8 services 文件写入  
  
- 用友GRP-U8 servlet 文件上传  
  
- 用友U8C 文件上传  
  
- 用友U8C 反序列化-1  
  
- 用友U8C 反序列化-2  
  
- 用友U8C esnserver文件写入  
  
- 用友U9 PatchFile 文件写入  
  
- 用友畅捷通T+密码重置  
  
- 用友畅捷通T+文件上传-1  
  
- 用友畅捷通T+文件上传-2  
  
- 用友畅捷通T+GetStoreWarehouseByStore反序列化  
  
- 用友KSOA ImageUpload 文件上传  
  
- 用友KSOA Attachment 文件写入  
  
- 用友移动管理平台Apk文件上传  
  
- 用友移动管理平台Icon文件上传  
  
- 用友U8-OA文件上传  
  
- 用友UFIDA NC 文件写入  
  
泛微已完成:  
- 泛微eoffice OfficeServer 文件上传  
  
- 泛微eoffice UploadFile 文件上传  
  
- 泛微eoffice uploadify 文件上传  
  
- 泛微eoffice ajax 文件上传  
  
- 泛微BshServlet 远程命令执行  
  
- 泛微ecology前台sql注入-1  
  
- 泛微ecology前台sql注入-2  
  
- 泛微ecology前台sql注入-3  
  
- 泛微ecology任意用户爆破  
  
- 泛微ecology任意用户登录-1  
  
- 泛微ecology任意用户登录-2  
  
- 泛微ecology FileClient 文件上传  
  
- 泛微ecology WorkflowServiceXml命令执行  
  
- 泛微ecology KtreeUploadAction 文件上传  
  
- 泛微ecology uploaderOperate 文件上传  
  
- 泛微ecology weaver.common.Ctrl 文件上传  
  
- 泛微ecology后台风格文件上传  
  
- 泛微ecology后台流程命令执行  
  
- 泛微ecology后台库存文件上传  
  
- 泛微emobile client命令执行  
  
- 泛微emobile messageType命令执行  
  
- 泛微emobile lang2sql文件覆盖  
  
蓝凌已完成:  
- 蓝凌OA 任意用户登录  
  
- 蓝凌OA SSRF  
  
- 蓝凌OA SSRF BeanShell 文件上传  
  
- 蓝凌OA SSRF XmlDecoder 文件上传  
  
- 蓝凌OA treexml 命令执行  
  
- 蓝凌OA界面文件上传  
  
- 蓝凌OA主题文件上传  
  
- 蓝凌OA jg_service文件上传  
  
- 蓝凌OA sysUiComponent文件复制  
  
- 蓝凌OA后台模板文件上传  
  
- 蓝凌EIS api文件上传  
  
万户已完成:  
- 万户OA用户密码泄露  
  
- 万户OA fileUpload 文件上传  
  
- 万户OA officeserverservlet 文件上传  
  
- 万户OA smartUpload 文件上传  
  
- 万户OA OfficeServer 文件上传  
  
- 万户OA senddocument 文件导入  
  
- 万户OA wpsservlet 文件上传  
  
- 万户OA SOAP 文件写入  
  
- 万户OA SOAP创建文件写入  
  
帆软报表已完成:  
- 帆软报表任意文件读取  
  
- 帆软报表任意文件读取-bypass  
  
- 帆软报表任意文件覆盖  
  
- 帆软报表未授权命令执行-1  
  
- 帆软报表未授权命令执行-2  
  
- 帆软报表未授权命令执行-3  
  
- 帆软报表channel命令执行-1  
  
- 帆软报表channel命令执行-2  
  
- 帆软报表ReportServer sql注入  
  
- 帆软报表后台插件文件上传  
  
- 帆软报表后台主题文件上传  
  
致远已完成:  
- 致远session泄露processUpload文件上传  
  
- 致远uploadMenuIcon文件上传  
  
- 致远ajax文件上传  
  
- 致远ajax文件上传-bypass  
  
- 致远wpsAssistServlet文件上传  
  
- 致远htmlofficeservlet文件上传  
  
- 致远任意用户密码重置  
  
- 致远audit-admin用户默认密码  
  
- 致远audit-admin用户重置密码  
  
- 致远后台模板文件上传  
  
- 致远后台模板管理器文件上传  
  
- 致远后台表格文件写入  
  
- 致远后台ofd文件解压  
  
- 致远后台jdbc文件写入  
  
- 致远后台constDef代码执行  
  
- 致远帆软报表文件读取  
  
- 致远帆软报表文件读取-bypass  
  
- 致远帆软报表日志命令执行  
  
- 致远帆软报表后台插件文件上传  
  
- 致远帆软报表后台主题文件上传  
  
- 致远M1命令执行  
  
通达已完成:  
- 通达任意用户登录-1  
  
- 通达任意用户登录-2  
  
- 通达任意用户登录-3  
  
- 通达任意用户登录-4  
  
- 通达Ispirit文件上传  
  
- 通达ueditor文件上传  
  
- 通达gateway反序列化  
  
- 通达后台附件文件上传  
  
红帆已完成:  
- 红帆OA任意文件上传  
  
- 红帆OA任意文件写入  
  
金和已完成:  
- 金和OA命令执行  
  
- 金和OA editeprint文件写入  
  
- 金和OA EditMain文件写入  
  
- 金和OA saveAsOtherFormatServlet文件上传  
  
- 金和OA OfficeServer文件上传  
  
- 金和OA UploadFileBlock文件上传  
  
- 金和OA servlet 文件上传  
  
- 金和OA jcsUploadServlet文件上传  
  
- 金和OA UploadFileEditorSave文件上传  
  
- 金和OA viewConTemplate 模板注入  
  
金蝶已完成:  
- 金蝶云星空反序列化-1  
  
- 金蝶云星空反序列化-2  
  
- 金蝶云星空反序列化-3  
  
- 金蝶云星空文件上传  
  
- 金蝶EAS file文件上传  
  
- 金蝶EAS logo文件上传  
  
- 金蝶Apusic 文件上传  
  
广联达已完成:  
- 广联达OA GetIMDictionary sql注入  
  
- 广联达OA 任意用户登录  
  
- 广联达OA 用户文件上传  
  
- 广联达OA 后台文件上传  
  
华天动力已完成:  
- 华天动力OA 登录绕过  
  
- 华天动力OA ntkoupload 文件上传  
  
- 华天动力OA Servlet文件上传  
  
  
  
  
**02**  
  
**工具使用**  
  
使用JDK8启动，命令如下：  
```
java -javaagent:Exp-Tools-1.3.1-encrypted.jar -jar Exp-Tools-1.3.1-encrypted.jar
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2U2qBVAzibC1dQt0bUFKqmbtUhwBLQyJRLEHyRqRBaqF60amaQTSYoPNMuic2w6Cc8CgHDAfsc37s0g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**03**  
  
**工具下载**  
  
****https://github.com/cseroad/Exp-Tools****  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
