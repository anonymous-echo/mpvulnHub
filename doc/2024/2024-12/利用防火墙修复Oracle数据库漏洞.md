#  利用防火墙修复Oracle数据库漏洞   
原创 ralap  网络个人修炼   2024-12-25 02:00  
  
最近，通过漏洞扫描系统发现了某些版本的Oracle数据库存在潜在的安全漏洞。这些漏洞如果被恶意利用，可能会对企业数据造成严重威胁。由于业务需求和技术限制，直接升级或停机修复这些漏洞变得不切实际。为了在不影响现有服务的前提下提升安全性，决定采用通过防火墙限制IP访问的方式来进行漏洞修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0QxpRutMQSmFeJwy1y6ia6ZOYXE31ibicJ8Yibpm5ondwefOW8lqje8ibGTRJpQ/640?wx_fmt=png&from=appmsg "")  
  
目标  
  
目标是通过防火墙规则实现严格的访问控制，仅允许来自特定IP地址或网段的请求访问Oracle数据库服务。  
#### 实施步骤  
####   
##### 一、Windows防火墙配置：  
  
打开 Windows Defender 防火墙高级安全  
：  
  
按  
Win + R  
 键,在运行窗口中输入  
wf.msc  
，然后按  
Enter  
。或在 Windows 搜索框中输入“Windows Defender 防火墙”，并选择“高级设置”。  
  
创建新的入站规则  
：在左侧面板中选择“入站规则”，然后在右侧面板中点击“新建规则”。选择“端口”，点击“下一步”。选择“TCP”，并在特定本地端口中输入1521（Oracle 数据库的默认端口），指定允许的 IP 范围  
：选择“允许连接”，点击“下一步”。在“配置文件”中选择适用的网络类型（域、私有、公用），然后点击“下一步”。在“名称”中为规则命名（例如“Oracle DB Access Control”），并添加描述（可选），然后点击“完成”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0Qxp7Abomu8gS3RUpj4KGh3UibVlxRlHABDfz8tLibib4dmuKGgFTI2FIPEqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0Qxp88zUMibH0LYia5baquTDibWZn7qUicsbFwSM8ftWFju70t5jbLlqszicIlQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0Qxp12MrXRQ6KKB87QKicT6BanctrBYKau7s0I8ouZoxbQj5bcc6hQXs8Ag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0Qxp7BETWKFcia2usiaENdxQRTo5MhJYwia4F6b6um7Txx9GGjQ79TkolmLlA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0QxpjC8VzMPMYdibC47KJHMZqqib8qLoZCW3tcg7c1e2v96LhYwYRSJVZWTg/640?wx_fmt=png&from=appmsg "")  
  
创建完成后，在添加的规则作用域输入允许的IP，点击保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0Qxpc9os99W5MichWIjBeib2ry0ysIXRyaUiaxy7lHw7B48G8qicygNsokbQibQ/640?wx_fmt=png&from=appmsg "")  
  
##### 二、Linux防火墙配置（以firewalld为例）：  
  
添加仅允许192.168.1.0段IP访问数据库1521端口  
  
```
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port protocol="tcp" port="1521" accept'
firewall-cmd --reload
```  
  
  
  
测试验证  
  
在添加防火墙规则之后，再次使用漏洞扫描系统进行了全面的安全检查。结果显示，之前检测到的相关漏洞已经不再出现，证明了通过防火墙限制IP访问这一方法的有效性  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfIiaowXSr1k1UrL4bzze0QxpCibOvYH2Y3K96HTyLoCib17xKpojUCPGWTENPAeTg2ghF3J1yd0f96ibQ/640?wx_fmt=png&from=appmsg "")  
  
总结  
  
总体而言，使用防火墙限制IP访问是一种实用且高效的临时或补充性安全措施。它能够在不中断业务的前提下迅速提升安全性，并为长期解决方案争取时间。然而，这不应被视为最终的安全策略。理想的做法是在条件允许的情况下，尽快应用官方发布的补丁或更新，从根本上解决问题。  
  
