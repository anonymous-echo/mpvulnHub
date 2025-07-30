#  警惕！ownCloud 文件共享程序中曝出三个严重漏洞   
 信息安全大事件   2023-11-27 18:23  
  
开源文件共享软件   
ownCloud 近日警告称存在三个严重安全漏洞，其中一个漏洞可能会暴漏管理员密码和邮件服务器凭证。  
  
ownCloud 是一款开源文件同步和共享解决方案，个人和组织均可通过这个自托管平台管理和共享文件。  
  
其用户包括企业、教育机构、政府机构和注重隐私的个人，他们希望数据自主可控，而不是将数据托管给第三方云存储提供商。据   
OwnCloud 网站报告，其安装量达 20 万次，拥有 600 家企业客户和 2 亿用户。  
  
该软件由多个库和组件组成，共同为云存储平台提供一系列功能。  
  
**严重的数据泄露风险**  
  
上周早些时候，该项目的开发团队发布了三个安全公告，警告称   
ownCloud 的组件中存在三个不同的漏洞，可能会严重影响其完整性。  
  
第一个漏洞被追踪为   
CVE-2023-49103，CVSS v3 最高分为 10 分。该漏洞可用于在容器化部署中窃取凭证和配置信息，影响网络服务器的所有环境变量。  
  
该漏洞影响了   
graphapi 0.2.0 至 0.3.0，问题源于该应用程序对第三方库的依赖，该库通过 URL 公开了 PHP 环境详细信息，从而暴露了 ownCloud 管理员密码、邮件服务器凭据和许可证密钥。  
  
官方建议的修复方法是删除   
"owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php "文件，禁用 Docker 容器中的 "phpinfo "函数，并更改可能暴露的机密，如 ownCloud 管理员密码、邮件服务器、数据库凭据和对象存储/S3 访问密钥。  
  
安全公告警告中强调称，仅仅禁用   
graphapi 应用程序并不能消除漏洞。  
  
此外，phpinfo 还暴露了其他各种潜在的敏感配置细节，攻击者可利用这些细节收集系统信息。因此，即使 ownCloud 没有在容器化环境中运行，这个漏洞仍应引起关注。  
  
第二个漏洞的   
CVSS v3 得分为 9.8，该漏洞可能影响 ownCloud 核心库 10.6.0 至 10.13.0 版本，涉及到身份验证旁路问题。  
  
如果用户的用户名已知且未配置签名密钥（默认设置），攻击者就有可能在未经身份验证的情况下访问、修改或删除任何文件。  
  
已公布的解决方案是，如果没有为文件所有者配置签名密钥，则拒绝使用预签名   
URL。  
  
第三个不太严重的漏洞（CVSS v3 得分：9），涉及到子域验证绕过问题，影响 0.6.1 以下所有版本的 oauth2 库。  
  
在   
oauth2 应用程序中，攻击者可以输入特制的重定向 URL，绕过验证码，将回调重定向到攻击者控制的域。  
  
官方建议采取的缓解措施是加固   
Oauth2 应用程序中的验证代码。公告中分享的临时解决方法是禁用 "允许子域 "选项。  
  
公告中描述的三个安全漏洞严重影响了   
ownCloud 环境的安全性和完整性，可能导致敏感信息暴露、隐蔽数据盗窃、网络钓鱼攻击等。  
  
文件共享平台的安全漏洞一直受到攻击，CLOP 等勒索软件组织利用这些漏洞对全球数千家公司进行数据盗窃攻击。  
  
官方建议ownCloud 的管理员立即应用建议的修复程序，以降低风险。  
  
来源：  
FreeBuf.COM  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-imgfileid="100005459" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=png&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
