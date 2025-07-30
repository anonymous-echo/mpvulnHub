#  【漏洞预警】用友nc 任意文件上传漏洞   
原创 MasterC  企业安全实践   2025-01-15 06:44  
  
一、漏洞描述  
  
用友NC是用友软件公司主打互联网平台型的ERP系统。  
  
用友NC系统存在任意文件上传漏洞。攻击者无需账号密码，可利用该漏洞上传恶意文件，进而完全控制主机。  
  
NC及NC CLOUD系统可利用/lfw/core/rpc 接口访问到 PortalSpecServiceImpl 中createSkinFile方法写入非法文件，从而控制服务器。  
  
二、漏洞等级  
  
高危  
  
三、受影响版本  
  
NC65、NCC2005  
  
四、安全版本  
  
参考官网修复版本。  
  
五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全版本。  
  
打对应补丁，重启服务，各版本补丁获取方式如下：  
  
1.NC65方案  
  
补丁名称：patch_portal65_lfw任意文件上传漏洞  
  
补丁编码：NCM_NC6.5_000_109902_20240301_GP_281362040  
  
校验码：  
  
c5b0569b76a6f9b9b9d6877a61f3539c73a3788ab74fade6889dcedff5353e9e  
  
2.NCC2005方案  
  
补丁名称：patch_portal2005_lfw任意文件上传漏洞  
  
补丁编码：NCM_NCCLOUD2020.05_10_109902_20240301_GP_281434197  
  
校验码：  
  
11656cd0bb32bf4ebe362d26e79014281a8d3df4bb09e9e5d00b1ffb46dda4d5  
  
六、缓解方案  
  
目前暂无缓解方案  
  
七、参考链接  
  
https://security.yonyou.com/#/noticeInfo?id=515  
  
  
