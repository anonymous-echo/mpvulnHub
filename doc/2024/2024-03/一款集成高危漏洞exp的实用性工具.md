#  一款集成高危漏洞exp的实用性工具   
 黑白之道   2024-03-03 09:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
# Exp-Tools  
### 介绍  
  
该工具使用了ExpDemo-JavaFX项目，保留了核心的数据包请求接口，使用jdk1.8环境开发。目前只编写了oa系列，对相关漏洞进行复现和分析，极力避免exp的误报和有效性。  
  
截止到目前为止，已实现了用友、泛微、通达、致远、帆软报表、万户、蓝凌、红帆、金和、华天动力总共10个OA。全部是命令执行、文件上传类的漏洞，包括前台和后台，未编写log4j、fastjson  
相关漏洞。  
  
用友已完成：  
- 用友NC-BshServlet 远程命令执行  
  
- 用友NC-BshServlet-bypass 远程命令执行  
  
- 用友NC accept 文件上传  
  
- 用友NC uapim 文件上传  
  
- 用友NC mp 文件上传  
  
- 用友U8CRM swfupload 文件上传  
  
- 用友U8CRM getemaildata 文件上传  
  
- 用友GRP-U8 UploadFileData 文件上传  
  
- 用友GRP-U8 U8AppProxy 文件上传  
  
- 用友GRP-U8 services 文件写入  
  
- 用友U8 cloud文件上传  
  
- 用友反序列化-1  
  
- 用友反序列化-2  
  
- 用友反序列化-3  
  
- 用友畅捷通T+文件上传  
  
- 用友KSOA ImageUpload 文件上传  
  
- 用友KSOA Attachment 文件写入  
  
- 用友NC Cloud 文件写入  
  
- 用友NC Cloud 文件上传  
  
- 用友移动管理平台Apk文件上传  
  
- 用友移动管理平台Icon文件上传  
  
泛微已完成:  
- 泛微OA KtreeUploadAction 文件上传  
  
- 泛微OA uploaderOperate 文件上传  
  
- 泛微OA weaver.common.Ctrl 文件上传  
  
- 泛微eoffice OfficeServer 文件上传  
  
- 泛微eoffice UploadFile 文件上传  
  
- 泛微eoffice uploadify 文件上传  
  
- 泛微eoffice ajax 文件上传  
  
- 泛微BshServlet 远程命令执行  
  
- 泛微ecology前台sql注入-1  
  
- 泛微ecology前台sql注入-2  
  
- 泛微ecology前台sql注入-3  
  
- 泛微ecology WorkflowServiceXml命令执行  
  
- 泛微ecology FileClient 文件上传  
  
- 泛微ecology后台风格文件上传  
  
- 泛微ecology后台流程命令执行  
  
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
  
- 蓝凌OA后台模板文件上传  
  
- 蓝凌EIS api文件  
上传  
  
万户已完成:  
- 万户OA用户密码泄露  
  
- 万户OA fileUpload 文件上传  
  
- 万户OA officeserverservlet 文件上传  
  
- 万户OA smartUpload 文件上传  
  
- 万户OA OfficeServer 文件上传  
  
- 万户OA senddocument 文件导入  
  
- 万户OA wpsservlet 文件上传  
  
- 万户OA SOAP 文件写入  
  
帆软已完成:  
- 帆软报表任意文件读取  
  
- 帆软报表任意文件读取-bypass  
  
- 帆软报表任意文件覆盖  
  
- 帆软报表未授权命令执行  
  
- 帆软报表channel命令执行  
  
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
  
- 致远后台模板文件上传  
  
- 致远后台模板管理器文件上传  
  
- 致远后台表格文件写入  
  
- 致远帆软报表文件读取  
  
- 致远帆软报表文件读取-bypass  
  
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
  
- 通达gateway  
反序列化  
  
- 通达后台附件文件上传  
  
红帆已完成:  
- 红帆OA任意文件上传  
  
- 红帆OA任意文件写入  
  
金和已完成:  
- 金和OA命令执行  
  
- 金和OA editeprint文件写入  
  
- 金和OA saveAsOtherFormatServlet文件上传  
  
- 金和OA OfficeServer文件上传  
  
- 金和OA jcsUploadServlet文件上传  
  
金蝶已完成:  
- 金蝶云星空反序列化  
  
- 金蝶云星空文件上传  
  
- 金蝶EAS  
 file文件上传  
  
- 金蝶EAS logo文件上传  
  
- 金蝶Apusic  
 文件上传  
  
华天动力已完成:  
- 华天动力OA ntkoupload 文件上传  
  
- 华天动力OA Servlet文件上传  
  
### 使用  
  
使用JDK8启动，命令如下：  
```
br
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/GzdTGmQpRic0FK2jPUukNZbzNEQnbXxx6tjb5ibTG6UcmS7e9Y3lIe9akEPUBk2hsSmiauIia3p12libjICeBd5YsSg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**工具下载**  
  
https://github.com/cseroad/Exp-Tools/releases/tag/v1.2.5  
  
**项目地址**  
  
https://github.com/cseroad/Exp-Tools  
  
> **文章来源：HACK之道**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
