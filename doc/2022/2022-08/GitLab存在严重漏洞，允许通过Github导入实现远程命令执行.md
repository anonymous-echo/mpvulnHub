#  GitLab存在严重漏洞，允许通过Github导入实现远程命令执行   
看雪学苑  看雪学苑   2022-08-25 18:02  
  
本周一，GitLab发布了其社区版（CE）和企业版（EE）的15.3.1、15.2.3、15.1.5版本，其中包含重要的安全修复程序。  
在公告中，GitLab强烈建议用户立即将其GitLab升级到这些版本之一，因GitLab CE/EE中存在一个高危漏洞。  
> GitLab是一个使用Git作为代码管理工具，并在此基础上搭建起来的Web服务，是目前被广泛使用的开源代码管理平台，适用于需要远程管理其代码的开发团队。GitLab拥有大约3000万注册用户和100万付费用户。  
  
  
  
  
根据GitLab官方公告，该漏洞（CVE-2022-2884）允许经过身份验证的用户通过从 GitHub API 端点导入来实现远程代码执行，是一个极为严重的问题（CVSS v3评分9.9）。该漏洞影响从11.3.4到15.1.5的所有版本、从15.2到15.2.3的所有版本，以及从15.3到15.3.1的所有版本。  
  
  
远程代码执行是一种十分危险的漏洞类型，利用此漏洞，攻击者  
能够在目标计算机上运行恶意代码  
、  
注入恶意软件  
和后门，以控制服务器、窃取或删除源代码、执行恶意提交等。  
  
  
通常，这种漏洞会在官方通过发布安全更新披露的几天后被大量利用。因此，GitLab强烈建议用户尽快进行安全更新。  
  
  
如果出于各种原因无法立即更新，GitLab建议用户暂时先采用下面的缓解措施保护自身免受此漏洞的影响：  
  
  
**禁用 GitHub 导入**  
  
  
使用管理员帐户登录到GitLab并执行以下操作：  
  
1、单击“菜单” - >“管理员”。  
  
2、单击“设置” - >“常规”。  
  
3、展开“可见性和访问控制”选项卡。  
  
4、在“导入源”下，禁用“GitHub”选项。  
  
5、点击“保存更改”。  
  
  
验证已正确实施缓解措施：  
  
1、在浏览器窗口中，以任何用户身份登录。  
  
2、单击顶部栏上的“+”。  
  
3、单击“新建项目/存储库”。  
  
4、点击“导入项目”。  
  
5、验证“GitHub”是否未显示为导入选项。  
  
  
  
编辑：左右里  
  
资讯来源：GitLab  
  
转载请注明出处和本文链接  
  
  
  
**每日涨知识**  
  
跳板攻击  
  
跳板攻击是目前黑客进行网络攻击的普遍形式。目前的各类攻击，无论其攻击原理如何，采用何种攻击手法，其攻击过程大多要结合跳板技术，进行攻击源的隐藏。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
