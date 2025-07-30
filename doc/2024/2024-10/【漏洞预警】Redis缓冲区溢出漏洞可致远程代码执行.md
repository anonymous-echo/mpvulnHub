#  【漏洞预警】Redis缓冲区溢出漏洞可致远程代码执行   
cexlife  飓风网络安全   2024-10-08 22:41  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00moV1AmezM74mM1VQeH7ljD5t72WfxvhepXibOccsdr68ghXhbowH9C5dASnqXkECo1tWDUp3OcRw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
Redis发布安全公告,修复了多个安全漏洞,其中包括一个缓冲区溢出漏洞,可致远程代码执行,经过身份验证的用户可能通过精心制作的Lua脚本在位库中触发堆栈缓冲区溢出,该问题存在于具有Lua脚本功能的Redis中,已在Redis版本6.2.16、7.2.6和7.4.1中修复,鉴于漏洞影响较大,建议用户立即采取措施。**修复建议:正式防护方案:**  
  
针对Redis堆栈缓冲区溢出导致的远程代码执行漏洞,用户需升级到Redis版本6.2.16、7.2.6或7.4.1以修复此问题。请按照以下步骤进行操作：  
  
1.备份当前Redis数据库以防止数据丢失2.下载并安装最新版本的Redis，可以从官方网站（https://redis.io/download）获取最新版本的安装包。3.更新Redis配置文件，确保新版本的Redis正确配置。4.停止当前Redis服务5.将旧版本的Redis二进制文件替换为新版本的二进制文件。6.启动新的Redis服务**官方产品补丁链接:**https://redis.io/download**参考链接:**https://github.com/redis/redis/commit/1f7c148be2cbacf7d50aa461c58b871e87cc5ed9  
  
