#  【漏洞预警】PHP远程代码执行   
 锦行科技   2022-06-14 16:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruDFMEnv2URhcnboZpfZvf2wgN1ag3Wn11S3WcqqKhSLMYiaLeJfRc9Kr6Qia3lPlgx1qsRIvTEI7EXA/640?wx_fmt=gif "")  
  
  
**前言**  
  
  
PHP（全称：PHP：Hypertext Preprocessor，即“PHP：超文本预处理器”）是一种开源的通用计算机脚本语言，尤其适用于网络开发并可嵌入HTML中使用。  
  
  
2022年6月9日，PHP发布安全公告，修复了两个存在于PHP中的远程代码执行漏洞。  
  
  
**漏洞名称：**  
  
PHP 多个远程执行代码漏洞  
  
**组件名称：**  
  
PHP  
  
**影响范围：**  
  
**CVE-2022-31625 范围：**  
  
5.3.0 <= PHP 5.x <= 5.6.40  
  
7.0.1 <= PHP 7.x < 7.4.30  
  
8.0.0 <= PHP 8.0.x < 8.0.20  
  
8.1.0 <= PHP 8.1.x < 8.1.7  
  
**CVE-2022-31626 范围：**  
  
7.0.1 <= PHP 7.x < 7.4.30  
  
8.0.0 <= PHP 8.0.x < 8.0.20  
  
8.1.0 <= PHP 8.1.x < 8.1.7  
  
**漏洞编号：**  
  
CVE-2022-31625、CVE-2022-31626  
  
**漏洞类型：**  
  
远程命令执行  
  
**利用条件：**  
  
无  
  
**综合评价：**  
  
<利用难度>：中  
  
<威胁等级>：  
**高危**  
  
  
**#1**  
**漏洞描述**  
  
  
**CVE-2022-31625**  
  
在PHP_FUNCTION中分配在堆上的的char* 数组没有被清除，如果发生转换错误，将会调用_php_pgsql_free_params()函数，由于数组没有初始化，导致可以释放之前请求的值，导致远程代码执行。  
  
  
**CVE-2022-31626**  
  
PHP的mysqlnd拓展中存在堆缓冲区溢出漏洞，利用该漏洞需要攻击者有连接php连接数据库的权限，通过建立恶意MySQL服务器，使受害主机通过mysqlnd主动连接该服务器，触发缓冲区溢出，从而在受害主机上导致拒绝服务或远程执行代码。基于php的数据库管理软件可能受该漏洞影响，如Adminer、 PHPmyAdmin 等工具。  
  
  
**#2 解决方案**  
  
  
目前官方已发布修复版本，用户可升级至以下安全版本：  
  
PHP 8.1.7  
  
PHP 8.0.20   
  
PHP 7.4.30  
  
  
**#3 参考资料**  
  
  
https://bugs.php.net/bug.php?id=81719  
  
https://bugs.php.net/bug.php?id=81720  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruD6rSnJpSL57NHjuX79JSjjyYviaibNeS3xmGzPfoict6VdnvyuYEq6JdjQqre3WkicWWU7hjpicS2ByibQ/640?wx_fmt=gif "")  
  
**推 荐 阅 读**  
  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489802&idx=1&sn=536036a9382203dec4a9366c1bec8ae9&chksm=9799e2afa0ee6bb9111845de90bc1f2fdb6ebb1a08206ddd90d89c6320da761e3cea6456cc32&scene=21#wechat_redirect)  
[守望相助，共克时艰——锦行党支部捐赠防疫物资助力疫情防控！](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489837&idx=1&sn=7ce6be87d1537a9f134f2bc358789465&chksm=9799e288a0ee6b9ed3a1d6518b34719ddd100c3dcc5d40225ea2fdc705f3a051fb63038c86ee&scene=21#wechat_redirect)  
  
[锦行科技获评2022届数博会领先科技成果“优秀项目”](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489802&idx=1&sn=536036a9382203dec4a9366c1bec8ae9&chksm=9799e2afa0ee6bb9111845de90bc1f2fdb6ebb1a08206ddd90d89c6320da761e3cea6456cc32&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489802&idx=2&sn=1d37181a955cf59e158d0d0589fa926b&chksm=9799e2afa0ee6bb963fcf05ed12a6d32ed776d1d67607d8ec69263e79c97e299ac545bd45269&scene=21#wechat_redirect)  
[【护网培训】锦行科技开展护网安全培训，赋能“数字经济服务站”](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489802&idx=2&sn=1d37181a955cf59e158d0d0589fa926b&chksm=9799e2afa0ee6bb963fcf05ed12a6d32ed776d1d67607d8ec69263e79c97e299ac545bd45269&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruBy67pKAiadAicicia5vPm2xla4zAiccf9wQm5dGGTWiaic61UXVZWCtnV8Vx2RNh2p2eHFnaSTJEhZ7LRxQ/640?wx_fmt=gif "")  
  
