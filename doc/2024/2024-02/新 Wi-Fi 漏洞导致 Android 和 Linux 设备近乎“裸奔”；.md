#  新 Wi-Fi 漏洞导致 Android 和 Linux 设备近乎“裸奔”；   
 网安百色   2024-02-25 19:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
  
**新 Wi-Fi 漏洞导致 Android 和 Linux 设备近乎“裸奔”；**  
  
  
网络安全研究人员发现，在安卓、Linux 和 ChromeOS 设备的开源 Wi-Fi 软件中存在两个身份验证绕过漏洞。据悉，安全漏洞可能诱使用户加入合法网络的恶意“克隆”，允许威胁攻击者在没有密码的情况下加入可信网络。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5P6u8siaI4U8jGdica5gZdFeD6N45m2JyoAibxy58dJrAg7uduW6TiagUevA/640?wx_fmt=jpeg&from=appmsg&wx_lazy=1&wx_co=1 "")  
  
> 安全研究人员对 wpa_supplicant 和英特尔的 iNet Wireless Daemon（IWD）进行安全评估后，发现分别被追踪为 CVE-2023-52160 和 CVE-2023-52161 的安全漏洞。  
  
  
  
Top10VPN 在与 Mathy Vanhoef 合作进行的一项新研究中表示， CVE-2023-52160 和 CVE-2023-52161 安全漏洞允许威胁攻击者诱骗受害者连接到受信任网络的恶意“克隆”中，并拦截其流量，最终成功在没有密码的情况下加入其他安全网络。  
  
  
特别是 CVE-2023-52161安全漏洞，该漏洞允许威胁攻击者未经授权访问受保护的 Wi-Fi 网络，从而使现有用户和设备面临恶意软件感染、数据盗窃和商业电子邮件泄露 (BEC)等潜在的网络攻击，主要影响 IWD 2.12 及更低版本。  
  
  
CVE-2023-52160 安全漏洞影响 2.10 及以前版本的 wpa_supplicant，鉴于其是安卓设备处理无线网络登录请求的默认软件，因此是上述两个安全漏洞中更紧迫的一个。  
  
  
值得一提的是，CVE-2023-52160 安全漏洞只会影响没有正确配置身份验证服务器证书的 Wi-Fi 客户端，CVE-2023-52161 则是影响使用 Linux 设备作为无线接入点 (WAP) 的任何网络。  
  
  
从研究人员发布的公告来看，成功利用 CVE-2023-52160 的前提条件是，威胁攻击者必须掌握受害者先前连接过的 Wi-Fi 网络的 SSID。此外，威胁攻击者必须与受害者保持合适的物理距离。（安全研究人员指出，利用该漏洞的最优情况是威胁攻击者在受害者附近四处走动，扫描网络，然后再瞄准离开办公室的员工。）  
  
  
目前，Debian (1, 2)、Red Hat (1)、SUSE (1, 2) 和 Ubuntu (1, 2) 等主要 Linux 发行版已针对上述安全漏洞发布了更新公告，ChromeOS 118 及更高版本也已解决了 wpa_supplicant 问题，但 Android 的修复程序目前仍旧尚未发布。  
  
  
最后，Top10VPN 强调，为保护自身安全性，Android 用户必须尽快手动配置任何已保存的企业网络 CA 证书，以防止遭遇网络攻击。  
  
  
> **文章来源 ：freebuf**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
