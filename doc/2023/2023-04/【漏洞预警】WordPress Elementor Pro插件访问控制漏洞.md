#  【漏洞预警】WordPress Elementor Pro插件访问控制漏洞   
安识科技  SecPulse安全脉搏   2023-04-04 11:45  
  
1. **通告信息**  
  
  
  
近日，安识科技  
A-Team团队监测到WordPress Elementor Pro 插件中修复了一个访问控制漏洞，其CVSSv3评分为8.8。经过身份验证的用户可利用该漏洞更改站点设置，甚至完全控制网站，目前该漏洞的细节已经公开，且已发现被利用。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
##   
  
2. **漏洞概述**  
  
  
  
漏洞名称：  
WordPress Elementor Pro插件访问控制漏洞  
  
简述：该漏洞涉及插件的  
WooCommerce模块（elementor-pro/modules/woocommerce/module.php）的访问控制失效，可能导致在没有适当验证的情况下修改数据库中的WordPress选项，可以通过易受攻击的 AJAX 动作“pro_woocommerce_update_page_option”来利用该漏洞（存在输入验证实施不当和缺乏功能检查）。未经身份验证的用户可以创建 WooCommerce 客户帐户，登录并利用该漏洞，通过启用注册和设置默认角色为 "管理员"来创建管理员账户，最终控制网站。  
##   
  
3. **漏洞危害**  
  
  
  
经过身份验证的用户可利用该漏洞更改站点设置，甚至完全控制网站。  
##   
  
4. **影响版本**  
  
  
  
目前受影响的  
WordPress Elementor Pro插件版本：  
  
WordPress Elementor Pro插件版本：<= 3.11.6  
##   
  
5. **解决方案**  
  
  
  
目前该漏洞已经修复，受影响的  
Elementor Pro用户可升级到：  
  
WordPress Elementor Pro插件版本：>= 3.11.7  
  
下载链接：  
https://elementor.com/  
pro/changelog/  
##   
  
6. **时间轴**  
  
  
  
【  
-】2023年04月02日 安识科技A-Team团队监测到漏洞公布信息  
  
【  
-】2023年04月03日 安识科技A-Team团队根据漏洞信息分析  
  
【  
-】2023年04月04日 安识科技A-Team团队发布安全通告  
  
  
         
  
