#  号卡极团分销管理系统 index.php SQL注入漏洞   
Superhero  Nday Poc   2024-10-23 21:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
号卡极团分销管理系统，同步对接多平台，同步订单信息，支持敢探号一键上架，首页多套UI+商品下单页多套模板，订单查询支持实时物流信息、支持代理商自定义域名、泛域名绑定，内置敢探号、172平台、号氪云平台第三方接口以及号卡网同系统对接！  
  
  
**01******  
  
**漏洞概述**  
  
  
号卡极团分销管理系统 /order/index.php 接口存在SQL注入漏洞，未经身份验证攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
icon_hash="-795291075"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKibSh1BuHtVq6BBG4V39EhefHlIYIamnPheAT13J9Lic9mSP3a70rtdzXcVmIWVEjicJQxufVCJX3ag/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKibSh1BuHtVq6BBG4V39EhemJKfwyxnVlicvJIxvxapgsTsZODuLPhYjGo3cntQe6mxbp4iasBhiaaKg/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKibSh1BuHtVq6BBG4V39EheclcGqdBibYkGOIg7YwGhafwsN2mMX2ffWLZeEc0NhpicwQ5Tgic7tQrrw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKibSh1BuHtVq6BBG4V39Ehezya87PpIYrA1Wia9ic3w1ySfjHFsibvjrTuqpj49ass45Yu9HBKLKXwkw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKibSh1BuHtVq6BBG4V39EheV8DrOmzEmZ7vqYFdHSiaMqjOPjV3OLP5nTZFfH8rJiboleqKPME7Zkcg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKibSh1BuHtVq6BBG4V39EhekFRv6p2s0IrRAu8RibBTibWX4g4vdvMzWRHylmkyySEI7ic8JT6Ze116Q/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、 升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
