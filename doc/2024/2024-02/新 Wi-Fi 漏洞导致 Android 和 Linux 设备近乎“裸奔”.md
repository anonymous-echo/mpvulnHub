#  新 Wi-Fi 漏洞导致 Android 和 Linux 设备近乎“裸奔”   
小王斯基  FreeBuf   2024-02-24 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5PIjY8afWx3ZUsxkZjpSgOa1CUXhH5Xibt0m65qVpfvtOfXnNYdvaVGzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5Pp5IlPWIsY8bhZztIibF8uXKAiba1hia5oM95FRdYtAfAropcldb941PqA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JS7Ca6vaeTUJaFVymhJGMXzmHn1ySEnUYII1IF3v1lgykt6deI9qlcddzvkRLicaYZ6MRrFfM5ERl/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JS7Ca6vaeTUJaFVymhJGMXzmHn1ySEnUYII1IF3v1lgykt6deI9qlcddzvkRLicaYZ6MRrFfM5ERl/640?wx_fmt=svg&from=appmsg "")  
  
  
  
网络安全研究人员发现，在安卓、Linux 和 ChromeOS 设备的开源 Wi-Fi 软件中存在两个身份验证绕过漏洞。据悉，安全漏洞可能诱使用户加入合法网络的恶意“克隆”，允许威胁攻击者在没有密码的情况下加入可信网络。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5P6u8siaI4U8jGdica5gZdFeD6N45m2JyoAibxy58dJrAg7uduW6TiagUevA/640?wx_fmt=jpeg&from=appmsg "")  
  
> 安全研究人员对 wpa_supplicant 和英特尔的 iNet Wireless Daemon（IWD）进行安全评估后，发现分别被追踪为 CVE-2023-52160 和 CVE-2023-52161 的安全漏洞。  
  
  
  
Top10VPN 在与 Mathy Vanhoef 合作进行的一项新研究中表示， CVE-2023-52160 和 CVE-2023-52161 安全漏洞允许威胁攻击者诱骗受害者连接到受信任网络的恶意“克隆”中，并拦截其流量，最终成功在没有密码的情况下加入其他安全网络。  
  
  
特别是 CVE-2023-52161安全漏洞，该漏洞允许威胁攻击者未经授权访问受保护的 Wi-Fi 网络，从而使现有用户和设备面临恶意软件感染、数据盗窃和商业电子邮件泄露 (BEC)等潜在的网络攻击，主要影响 IWD 2.12 及更低版本。  
  
  
CVE-2023-52160 安全漏洞影响 2.10 及以前版本的 wpa_supplicant，鉴于其是安卓设备处理无线网络登录请求的默认软件，因此是上述两个安全漏洞中更紧迫的一个。  
  
  
值得一提的是，CVE-2023-52160 安全漏洞只会影响没有正确配置身份验证服务器证书的 Wi-Fi 客户端，CVE-2023-52161 则是影响使用 Linux 设备作为无线接入点 (WAP) 的任何网络。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5P09QiaBnV4QmNQyuaO4G8J9LwACWS5qbuTZVnTB5za9cLz90O6VIMl5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
从研究人员发布的公告来看，成功利用 CVE-2023-52160 的前提条件是，威胁攻击者必须掌握受害者先前连接过的 Wi-Fi 网络的 SSID。此外，威胁攻击者必须与受害者保持合适的物理距离。（安全研究人员指出，利用该漏洞的最优情况是威胁攻击者在受害者附近四处走动，扫描网络，然后再瞄准离开办公室的员工。）  
  
  
目前，Debian (1, 2)、Red Hat (1)、SUSE (1, 2) 和 Ubuntu (1, 2) 等主要 Linux 发行版已针对上述安全漏洞发布了更新公告，ChromeOS 118 及更高版本也已解决了 wpa_supplicant 问题，但 Android 的修复程序目前仍旧尚未发布。  
  
  
最后，Top10VPN 强调，为保护自身安全性，Android 用户必须尽快手动配置任何已保存的企业网络 CA 证书，以防止遭遇网络攻击。  
  
  
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
> https://thehackernews.com/2024/02/new-wi-fi-vulnerabilities-expose.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492409&idx=1&sn=0989200153f6f4679af989e0852c8789&chksm=ce1f19a6f96890b01a5f5cab663742e640859aa44f27f3bb31eb0eca8c2fd920bdb9839a5c19&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492374&idx=1&sn=0b847c8f0f000881d8efc5c646ef4181&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
