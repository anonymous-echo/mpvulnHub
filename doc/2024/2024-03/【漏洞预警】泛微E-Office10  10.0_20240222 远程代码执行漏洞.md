#  【漏洞预警】泛微E-Office10 < 10.0_20240222 远程代码执行漏洞   
cexlife  飓风网络安全   2024-03-28 22:18  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00jyLOWib7PSOzrtdIU5PUeWmJ6cpzibXZnY9z18Gg38MSnelZyTyMAiaCcUxthPsXgEDJNGibQ46JjcA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
泛微e-office OA系统是通过php开发面向中小型组织的专业协同OA软件,在受影响版本中,由于处理上传的phar文件时存在缺陷,攻击者可通过向/eoffice10/server/public/api/attachment/atuh-file等地址上传恶意phar文件,利用针对phar的反序列化触发远程代码执行。**影响范围:**e-office10[10.0_20180516, 10.0_20240222)**修复方案:**将组件 e-office10升级至10.0_20240222及以上版本  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00jyLOWib7PSOzrtdIU5PUeWkEJOsbIqlneicTBDxTg8sIweicvzWmJicXsibsXG8n5iczB2RyZSfxxWW1Q/640?wx_fmt=png&from=appmsg "")  
**参考链接：**https://service.e-office.cn/knowledge/detail/5  
