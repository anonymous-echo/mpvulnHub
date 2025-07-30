#  SolarWinds 曝出五个严重的 RCE 漏洞   
小王斯基  FreeBuf   2024-02-18 18:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bC4UK3D5tY0zXYKPZKFMSUQdR2yUkGGo8x2icrffD1O5qyqQiatt0SWQHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bCfYHY7oTCBJCKtkia8uueMI6qFJ9hiaPLicqKWfFE0LuE0MQFPzmdztVcA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bCZlaSfSPQxia4p3Mica9n9s2awrvonXib2Bx4uicSFGiaZIhRlsibujxbFZ5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcYhD4pUB14wbicCZjrPUFngjSbnjhZIp41RopPTuKK6RD3QmbDL3qegutEYlcurL3JKqAI3rsgDL/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcYhD4pUB14wbicCZjrPUFngjSbnjhZIp41RopPTuKK6RD3QmbDL3qegutEYlcurL3JKqAI3rsgDL/640?wx_fmt=svg&from=appmsg "")  
  
  
  
  
SolarWinds 近期修补了 Access Rights Manager (ARM) 解决方案中的五个远程代码执行 (RCE) 漏洞，其中包括三个允许未经验证利用的严重安全漏洞！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bCdicoQSEpf9md39syxQAZwj3Cf4GiahyCYqPCdQOVMpMJYWsxk8RyHtgg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**漏洞详情**  
  
  
CVE-2024-23476 和 CVE-2024-23479 安全漏洞由于路径遍历问题引发，第三个严重安全漏洞 CVE-2023-40057 由反序列化不受信任的数据造成，一旦未经身份验证的威胁攻击者成功利用这三个安全漏洞，便可以轻松在未打补丁的目标系统上执行任意代码。  
  
  
另外两个安全漏洞 CVE-2024-23477 和 CVE-2024-23478 被 SolarWinds 评定为高严重性安全漏洞，可以被威胁攻击者用来 RCE 攻击。  
  
  
值得一提的是，上述提到的安全漏洞中有四个由 ZDI 匿名安全研究人员发现并报告，剩余一个则是 ZDI 漏洞研究人员 Piotr Bazydło 发现并上报。据悉，SolarWinds 在本周发布的 Access Rights Manager 2023.2.3 中解决了安全漏洞问题，并进行安全修复。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bCkrMMF8yJTqWxPHWlM700ckEicq18ZotevjEZJMp1GWFJMbiaZhMgp2cg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
安全漏洞问题曝出后，SolarWinds 发言人第一时间对外表示，目前尚未收到任何关于这些漏洞在野外被利用的报告。此外，公司在获悉漏洞信息后，立刻与客户取得了联系，以确保其能够采取有效措施，避免遭受网络攻击。后续也立即发布了安全更新，用户能够通过补丁程序，最大程度上解决安全漏洞问题。  
  
  
值得一提的事，SolarWinds 曾在 2023 年 10 月份修复了另外三个关键的 Access Rights Manager RCE 漏洞，这些安全漏洞允许威胁攻击者以 SYSTEM 权限运行代码。  
  
  
**2020 年 3 月 SolarWinds 供应链攻击事件**  
  
  
  
SolarWinds 在全球范围内有广泛的客户群体，拥有超过 30万客户，为包括苹果、谷歌和亚马逊等知名公司，以及美国军方、五角大楼、国务院、美国国家航空航天局、美国国家安全局、邮政局、美国海洋和大气管理局、司法部和美国总统办公室等政府组织在内的机构提供服务。因此，早就成为了威胁攻击者眼中的“香饽饽”。  
  
  
几年前，SolarWinds  公司曾发生了一起严重的供应链攻击事件，对全球多个组织带来了恶劣影响。  
  
  
起因是 APT29 黑客组织渗透了 SolarWinds 的内部系统，将恶意代码注入到了客户在 2020 年 3 月至 2020 年 6 月期间下载的 SolarWinds Orion IT 管理平台构建中，为  
威胁攻击者在数以千计的系统上部署 Sunburst 后门提供了便利，使其能够有选择性地针对潜在受害目标，开展网络攻击活动。  
  
  
供应链攻击事件披露后，包括国土安全部、财政部和能源部，以及国家电信和信息管理局（NTIA）、国家卫生研究院和国家核安全局在内的多个美国政府机构证实自身遭到了网络入侵。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> https://www.bleepingcomputer.com/news/security/solarwinds-fixes-critical-rce-bugs-in-access-rights-audit-solution/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492374&idx=1&sn=0b847c8f0f000881d8efc5c646ef4181&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492331&idx=1&sn=406428ff5a9e185e658948e896b0b4a8&chksm=ce1f1874f9689162105cf92ee082dcafbd164bbe3fb15d3bde4d4c8328c2ac2d3526fd006d84&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
