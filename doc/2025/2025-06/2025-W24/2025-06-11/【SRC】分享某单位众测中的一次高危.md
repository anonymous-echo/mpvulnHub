#  【SRC】分享某单位众测中的一次高危  
 不秃头的安全   2025-06-11 09:04  
  
## 某单位众测中的一次高危  
```
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。还在学怎么挖通用漏洞和src吗？知识星球有什么，文章下限时优惠卷~~想要入交流群在最下方，考安全证书请联系vx咨询。
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWaOQhXOf0cibja9IiaN9XvbmE5jLs5PByGh6NEsygeaAwonoQf8yKn2DtF6ZC0FshCkm3icyxic2lWqQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
1、首先是在 xxxxxxx平台查看全站企业内部员工信息  
  
首先在小程序开通vip，最低档的5元即可，之后获得web端的进入权限  
  
https://xxxxxxx/Login  
  
2、找到这个系统的登陆界面，直接先登陆即可  
  
然后在系统里面尝试刷新下页面，这里注意观察页面或者数据包的一个回显操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoo44icbWClZw0QTn4d1VtX3oscmSScOdxzQC7LgCjCDfx0Yk0RTibfc3g/640?wx_fmt=png&from=appmsg "")  
  
3、开启f12，开始js逆向  
  
搜索：  
Ou.prototype.fetch  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARogHOBVkIhXHYtMEUQeDTMoRXEDZXZSUIdvqAx0fKqtHM6HDrrdPRbOg/640?wx_fmt=png&from=appmsg "")  
  
  
4、这里直接经过js逆向操作，然后打断点，分析函数和相关接口，进行分析，可以看到这里出现了一个ID值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoJGcvasqU3EiarkcXb1RLBtX00dlE9elibNxATfJCXqJuWp258gkG64eg/640?wx_fmt=png&from=appmsg "")  
  
  
5、修改r的id值为被越权企业的epId值  
  
QYxxxxxx3334600198  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARo54aiczianyUoaIOxyat7mcOZoEtlibcFlzZ8M6mH1tF2ibRs5V2PtjibIHA/640?wx_fmt=png&from=appmsg "")  
  
  
6、师傅们这里就可以直接看到B角色的账号信息了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoPNt4bdsrmuo8f3MdklvUp4L7xhc0vtWsaMJxFnLmWCOUjPUroMNBgQ/640?wx_fmt=png&from=appmsg "")  
  
然后还可以获取其他用户人员的epid值，然后可以直接未授权看到其他公司的敏感数据了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoBCJH7BgviauEv8CjrOE601YJDFgF7q6v0Sa3Saq5HlmlwvWKNteKD2g/640?wx_fmt=png&from=appmsg "")  
  
  
7、这里给师傅们分享下这次进行AES密钥解密的一个过程，如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoVfeNWDS4wEHNBAC68V67qFxBygKa1K1tSkRvMicXogNZfs1CbSz2wxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARo1ibKrtmBaUuhXFcs905LsUZsdBdhR6oNicX5r19cjicPFtNkJTng0JRTg/640?wx_fmt=png&from=appmsg "")  
  
  
8、师傅们可以看，  
可以看到这里有xx公司本身以及旗下的子公司的名片，数据量巨大  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoEbeZxOibKzSP3wTctCXODaJXD6Lz39TV24qFIIwDvqX94pDAmQf7XwQ/640?wx_fmt=png&from=appmsg "")  
  
  
光是加载部分公司的数据，返回包已经来到了710494  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARot5n1w5gWIFCPMyavd8YEf2wudPqdFtwaJerLcAf8JcyvUqMIrmGrnA/640?wx_fmt=png&from=appmsg "")  
  
  
泄露全部注册企业的人员信息，最后也是直接众测高危到手，直接几千块的SRC赏金，也是很香啊～  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARofdXD763OjhPia6jNbC6pxeic1IHmerfmEzCfm7KbciaibyegXlN8nFm67Q/640?wx_fmt=png&from=appmsg "")  
  
往期推荐：  
  
[工具分享 | 后渗透内网一键自动化+无文件落地扫描工具](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489439&idx=1&sn=a221fdb81e310358211200e30ce7d0b3&scene=21#wechat_redirect)  
  
  
[EasyTools 一个简单方便使用的渗透测试工具箱 v1.7.4 更新！！](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489375&idx=1&sn=45b13dd719f652e755051db9ab3bc681&scene=21#wechat_redirect)  
  
  
[工具分享 | 自动文件上传绕WAF工具](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489241&idx=1&sn=240640a363431beb97932c62e47c3dbb&scene=21#wechat_redirect)  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fW8bMyZp3c05D8XljRicbts59CDm6kHKtwImw2KD9bxfUJR2FUhiaJeFHuIOZctgWTx1icsvUt7VaHcg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
## 1. 需要考以下各类安全证书的可以联系  
  
学生pte超低价，绝对低价绝对优惠，CISP、PTE/PTS、DSG、IRE/IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理等等巨优惠，想加群下方链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVbuDda6lRd1bS4RbMPV90waXWiaM6NoKyQmqGiabs4IQ8nAuFppJ77sX9xzWCo8ojiar7CGSKVLDicHA/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fW8bMyZp3c05D8XljRicbts5D3Uy5k9ERxwp7WiaCQLwHkuWlvoxrfvjicqmPgSlzXKmgk3wFuZAXqibQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&watermark=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fW8bMyZp3c05D8XljRicbts5q5LmNm2Pz3VjvM8kbbQx22fggecEuO8iaN1BwZZrGnHctAw0jib9W9OQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
## 2. 需要入星球的可以私聊优惠  
  
投稿文章可免费进星球~~星球里有什么？  
```
1、维护更新src、cnxd、cnnxd专项漏洞知识库，包含原理、挖掘技巧、实战案例2、fafo/零零信安/QUAKE 高级会员key3、POC及CXXD及CNNXD通用报告详情分享思路4、知识星球专属微信“内部圈子交流群”5、分享src挖掘技巧tips6、最新新鲜工具分享7、不定期有工作招聘内推（工作/护网内推）8、攻防演练资源分享(免杀，溯源，钓鱼等)9、19个专栏会持续更新~提前续费有优惠，好用不贵很实惠
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fW8bMyZp3c05D8XljRicbts5QU6FtqXOVEvVTMOsTMjolBl81KGBonDejr2Dak0X6ibC8kOHI3ULiaPg/640?wx_fmt=jpeg&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
## 3、其他合作（合法合规）  
  
1、承接各种安全项目，需要攻防团队或岗位招聘都可代发、代招（灰黑勿扰）；  
  
2、各位安全老板需要文章推广的请私聊，承接合法合规推广文章发布，可直发、可按产品编辑推广；  
合作、推广代发、安全项目、岗位代招均可发布![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fW8bMyZp3c05D8XljRicbts5E8JDrOxsYdpFrw43ljft5llr5SKrYd583FvNF1icasn14q8E0gZAEjQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
  
  
