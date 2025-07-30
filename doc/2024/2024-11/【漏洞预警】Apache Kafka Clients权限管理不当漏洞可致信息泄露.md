#  【漏洞预警】Apache Kafka Clients权限管理不当漏洞可致信息泄露   
cexlife  飓风网络安全   2024-11-19 13:50  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu019dc8yxarexIEx97oF3hOtlTibx7hfaz4tCFJPXcoJxUDS1GYa7gG4Hxh5VyaHSqeHFKmNZ8PnpGQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Kafka官方发布安全公告,修复了Apache Kafka Clients中存在的一处权限管理不当漏洞,可导致文件和目录可被外部访问。该漏洞是由于Apache Kafka Clients的配置可能被不可信方指定,攻击者可利用ConfigProvider插件读取磁盘内容和环境变量,官方已针对此漏洞发布3.8.0版本,建议受影响用户升级 kafka-clients到3.8.0及以上版本以缓解此漏洞。**修复建议:正式防护方案:**针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:Apache Kafka Clients >= 3.8.0**下载链接:**https://kafka.apache.org/downloads安装前，请确保备份所有关键数据，并按照官方指南进行操作。安装后，进行全面测试以验证漏洞已被彻底修复，并确保系统其他功能正常运行。**参考链接:**https://lists.apache.org/thread/9whdzfr0zwdhr364604w5ssnzmg4v2lv  
  
