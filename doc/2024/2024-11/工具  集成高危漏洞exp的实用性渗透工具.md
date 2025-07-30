#  工具 | 集成高危漏洞exp的实用性渗透工具   
 渗透安全团队   2024-11-18 03:02  
  
由于微信公众号推送机制改变了，快来  
**星标**  
不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DungicHdGVdJpoQp8uIUIs13xBa1eTRSObiczwsfbtDvKU0ibAfkHegDGV2o4daf95jVdO9rnFeny7A/640?wx_fmt=png "")  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8BpaQTHrjCa8ph7r5AEqcOaZHwwjdo5gD6TD716tjzuW9Su1Jces18as8Qz7rY0aBdA7crtCeyxLw/640?wx_fmt=jpeg "")  
  
  
**03**  
  
**工具下载**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
**翻到文章最底部点击“阅读原文”下载链接**  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  
[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247513602&idx=1&sn=98045772ff9aebe8792552e32523bf83&chksm=c1764badf601c2bbcc199da519611ac8c36c17e5a0554fe32ab9d9769403a495187058f19f3d&scene=21#wechat_redirect)  

			                  
  
  
**信 安 考 证**  
  
  
  
需要考以下各类安全证书的可以联系我，下方扫码回复  
**考证**  
进交流群，价格优惠、组团更便宜，还送【  
渗透安全团队  
】知识星球**1**年！  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;"><td width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;"><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">CISP、PTE、PTS、DSG、IRE、IRS、</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">NISP、</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">PMP、CCSK、CISSP、ISO27001...</span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**教程如下图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8C3Gu1libJC0muV1WmOFa3XM3fTyOiaOJYPgCiaHV6gkJJBia6Fjeds9w9pxxyyPNJhbcfK3I1tcGueTg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
