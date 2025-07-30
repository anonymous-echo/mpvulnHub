#  【神兵利器】Jeecg综合漏洞利用工具   
MInggongK  七芒星实验室   2024-12-03 23:05  
  
项目介绍  
  
Jeecg综合漏洞利用工具程序采用javafx开发，环境JDK 1.8 声明：仅用于授权测试，用户滥用造成的一切后果和作者无关 请遵守法律法规  
  
漏洞支持  
- jeecg-boot queryFieldBySql远程命令执行漏洞  
  
- jeecg-boot testConnection远程命令执行漏洞  
  
- JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
- jeecg-boot-queryTableData-sqli注入漏洞  
  
- jeecg-boot-getDictItemsByTable-sqli注入漏洞  
  
- Jeecg-Boot qurestSql-SQL注入漏洞  
  
- jeecg-boot commonController 任意文件上传漏洞  
  
- jeecg-boot jmreport任意文件上传漏洞  
  
- jeecg-boot-querySysUser信息泄露漏洞  
  
- jeecg-boot-checkOnlyUser信息泄露漏洞  
  
- jeecg-boot-httptrace信息泄露漏洞  
  
- jeecg-boot-任意文件下载漏洞  
  
- jeecg-boot-jeecgFormDemoController漏洞  
  
- jeecg-boot-v2 P3 Biz Chat任意文件读取漏洞  
  
- jeecg-boot-v2 sys/duplicate/check注入漏洞  
  
- jeecg-boot-v2 AviatorScript表达式注入漏洞  
  
功能介绍  
  
Jeecg综合漏洞利用工具集成了多模块漏洞利用，包括一键漏洞检测，单独选择模块检测,cmdshell模块，文件上传模块，批量检测模块等 v3.0版本内置的标准库外，在检测模块加入了okhttp的三方库，支持https网站检测，以及优化了基于jeecg queryUser漏洞的接口测试  
  
(1) 一键检测模块，选择模块  
- jeecg-boot queryFieldBySql远程命令执行漏洞  
  
- jeecg-boot testConnection远程命令执行漏洞  
  
- JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
- jeecg-boot-queryTableData-sqli注入漏洞  
  
- jeecg-boot-getDictItemsByTable-sqli注入漏洞  
  
- Jeecg-Boot qurestSql-SQL注入漏洞  
  
- jeecg-boot commonController 任意文件上传漏洞  
  
- jeecg-boot jmreport任意文件上传漏洞  
  
- jeecg-boot-querySysUser信息泄露漏洞  
  
- jeecg-boot-checkOnlyUser信息泄露漏洞  
  
- jeecg-boot-httptrace信息泄露漏洞  
  
（2）接口测试模块  
- jeecg-boot-querySysUser信息泄露漏洞  
  
- jeecg-boot-checkOnlyUser信息泄露漏洞  
  
（3）cmdshell模块:  
- jeecg-boot queryFieldBySql远程命令执行漏洞  
  
- jeecg-boot testConnection远程命令执行漏洞  
  
- JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
(4) 文件上传模块:  
- jeecg-boot commonController 任意文件上传漏洞  
  
- jeecg-boot jmreport任意文件上传漏洞  
  
(5)批量检测模块：  
- jeecg-boot queryFieldBySql远程命令执行漏洞  
  
- jeecg-boot testConnection远程命令执行漏洞  
  
- JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
- jeecg-boot-queryTableData-sqli注入漏洞  
  
- jeecg-boot-getDictItemsByTable-sqli注入漏洞  
  
- Jeecg-Boot qurestSql-SQL注入漏洞  
  
使用示例  
  
默认模块可一键扫描所有漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickBdBGk1KVB2wSzvxcDtvbGYLXc2HonM1z6sS5vJh0ZTMP5QcuDdyFW8uyf2JRJmtUHfTBglVZSdg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickBdBGk1KVB2wSzvxcDtvbG3Xmg6licfxZz5cRqq2NeNTJyc8jibbFSLXdqPlLg3Cwo2fUB29cxm1Bw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickBdBGk1KVB2wSzvxcDtvbGlprRBAWKh0E9gWI90eq0OCBKonXnaiam3ic0hbLB5iatrTLpT7AqlOZcg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickBdBGk1KVB2wSzvxcDtvbG8RCqVeASzaIEU8njTH7BzEyeZEOicWVcTvjuEuPYueuwCFdQBd0w6icA/640?wx_fmt=png&from=appmsg "")  
  
命令执行：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickBdBGk1KVB2wSzvxcDtvbGtjh07H1LdLafziafXPZacFXHqeQGe2PnAzhSBtZ0Cx2bQiaMh6gEJYAA/640?wx_fmt=png&from=appmsg "")  
  
文件上传：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickBdBGk1KVB2wSzvxcDtvbGEySnhnAibkqDmc4uiaYKXl10PW7QUDs72hLWx7kic4XY8kTGj3prWWTSQ/640?wx_fmt=png&from=appmsg "")  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**241204****】获取**  
**下载链接**  
  
**·推 荐 阅 读·**  
  
# 最新后渗透免杀工具  
# 【护网必备】高危漏洞综合利用工具  
#   【护网必备】Shiro反序列化漏洞综合利用工具增强版  
# 【护网必备】外网打点必备-WeblogicTool  
# 【护网必备】最新Struts2全版本漏洞检测工具  
# Nacos漏洞综合利用工具  
# 重点OA系统漏洞利用综合工具箱    
# 【护网必备】海康威视RCE批量检测利用工具  
# 【护网必备】浏览器用户密码|Cookie|书签|下载记录导出工具  
  
  
  
