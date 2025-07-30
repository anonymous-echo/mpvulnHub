#  某木报表RCE_0day   
原创 M9  白昼信安   2024-07-30 20:14  
  
1、漏洞描述  
  
接口是积木报表自带接口，正常访问会提示权限不足，但利用jmLink=YWFhfHxiYmI=可绕过权限校验。绕过权限校验后，可在请求体中注入内存马，可获取服务器权限。  
  
2、漏洞路径  
  
/jeecg-boot/jmreport/save?previousPage=xxx&jmLink=YWFhfHxiYmI=  
  
使用该系统可以重点关注  
jmLink=参数，加强监控  
  
  
