#  漏洞预警 | YourPHPCMS SQL注入漏洞   
浅安  浅安安全   2024-12-14 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
YourphpCMS是一款完全开源免费的PHP+MYSQL系统，强大灵活的后台管理功能、任何添加多国语言功能、静态页面生成功能、自定义模型功能、自制插件安装管理功能、自定义幻灯片模板等可为企业打造出大气漂亮且具有营销力的精品网站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUlxtwpd4P0rFf3icGicd7SNw4vtlv42nc4bia0Lz3Con4ka9BbzSKicNZbYfQzEnL7fcricnPyH42FwvQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
YourphpCMS的/index.php?g=User&m=Register&a=checkEmail和/index.php?g=Admin&m=Login&a=checkEmail接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- YourphpCMS  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://github.com/yunsite/yourphpcms/  
  
  
  
