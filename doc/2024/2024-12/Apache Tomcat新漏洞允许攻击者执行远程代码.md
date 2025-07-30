#  Apache Tomcat新漏洞允许攻击者执行远程代码   
 网安百色   2024-12-20 11:32  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
据Cyber Security News消息，安全研究人员在流行的开源 Web 服务器 Apache Tomcat和servlet 容器中发现了两个严重漏洞，可能允许攻击者执行远程代码并导致拒绝服务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icherY4cPanJaomibfQGLiaY8v6AyRuaXIGicaicQ0qDA1muqfNckzOCgibibzOXBlZhlfPuxutJEwOmKrA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
第一个漏洞被追踪为 CVE-2024-50379， 影响   
Apache Tomcat  
  11.0.0-M1 到 11.0.1、10.1.0-M1 到 10.1.33 和 9.0.0.M1 到 9.0.97版本 。如果默认 servlet 在不区分大小写的文件系统上配置了写入权限，攻击者可在并发读取和上传操作期间利用竞争条件。这种绕过 Tomcat 大小写敏感性检查的做法会导致上传的文件被视为 JSP，最终导致远程代码执行。  
  
  
第二个漏洞被追踪为 CVE-2024-54677，虽然严重性较低，但仍可能构成重大威胁。它影响相同版本的 Apache Tomcat，可使攻击者触发  
拒绝服务攻击  
。该漏洞源于 Tomcat 提供的 Web 应用程序示例，其中许多示例无法限制上传的数据大小，可能会导致 OutOfMemoryError，从而导致拒绝服务。  
  
值得注意的是，默认情况下，示例网络应用程序只能从 localhost 访问，这在一定程度上限制了潜在的攻击面。  
  
  
目前Apache 已经发布了解决这些安全漏洞的补丁，敦促用户立即升级：  
  
- Apache Tomcat 11.0.2 或更高版本  
  
- Apache Tomcat 10.1.34 或更高版本  
  
- Apache Tomcat 9.0.98 或更高版本  
  
这些漏洞的发现突显了在网络服务器环境中定期进行安全审计和及时打补丁的重要性。由于 Apache Tomcat 在企业环境中的广泛使用，因此这些漏洞的潜在影响十分巨大。  
  
  
最近，Apache还披露了一个CVSS 4.0 评分高达9.5的高危漏洞，影响Apache Struts 2.0.0 到 2.3.37、2.5.0 到 2.5.33 以及 6.0.0 到 6.3.0.2版本，攻击者可以操纵文件上传参数以启用路径遍历，在某些情况下，这可能导致上传可用于执行远程代码执行的恶意文件 。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
