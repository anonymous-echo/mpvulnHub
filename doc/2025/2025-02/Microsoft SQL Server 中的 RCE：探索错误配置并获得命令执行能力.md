#  Microsoft SQL Server 中的 RCE：探索错误配置并获得命令执行能力   
 Ots安全   2025-02-02 14:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tafH6VqrPCuic5vS8w0fian9nWVGiaHJAxjAGDYRYrmG10K89t2A7xaic1PVQffia56f9vjsQ06pMWdJZGA/640?wx_fmt=jpeg&from=appmsg "")  
  
本文将探讨如何从 Microsoft SQL Server (MSSQL) shell 升级到在目标计算机上执行命令。这可以通过使用名为 xp_cmdshell 的内置 MSSQL 功能来实现。  
  
这种攻击比最初看起来要严重得多。虽然该进程是从 MSSQL 外壳启动的，但也可通过 SQL 注入 (SQLi) 攻击加以利用。如果攻击者能够注入 SQL 命令，他们就能利用这一漏洞在系统上执行命令。  
  
**攻击概述**  
  
让我们深入了解一下这次攻击。首先，我要概述一下当前的情况：我可以访问一个 Microsoft SQL shell，它看起来像这样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafH6VqrPCuic5vS8w0fian9nWbOwJSDypaWPkCXe2yrvzmMOB4JEz78dCDXBob9Upib1xKaVYkIib192A/640?wx_fmt=png&from=appmsg "")  
  
至此，我们已经准备好执行第一条 SQL 命令，尝试在本地计算机上运行命令。如前所述，我们将使用 xp_cmdshell 功能来实现这一目标。  
  
```
xp_cmdshell "whoami"
```  
  
  
该命令通过 SQL Server 的 xp_cmdshell 功能执行 whoami 实用程序。whoami 命令只是返回当前执行进程的用户--在本例中，即运行 SQL Server 的用户。通过运行 xp_cmdshell 'whoami'，可以确定目标计算机上 SQL Server 服务账户的权限。该信息对于确定您的访问权限级别至关重要，如果 SQL Server 服务以高于预期的权限运行，则可能有助于提升您的权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafH6VqrPCuic5vS8w0fian9nWs6nanj7fqNjo8RtrDGxLaSdjN3miaeIMm0bNicTBuIjZXPqskCUpMAHg/640?wx_fmt=png&from=appmsg "")  
  
不幸的是，初次尝试没有成功。查看错误信息后发现，似乎缺少某些权限。不过，由于我已经以管理员身份登录了 MSSQL shell，下一步就是修改两个配置设置，以便再次尝试执行命令。  
  
```
SP_CONFIGURE "show advanced options", 1
```  
  
  
  
```
RECONFIGURE
```  
  
  
该命令可在 SQL Server 中启用高级选项。SP_CONFIGURE 命令用于修改服务器级别的配置。通过设置 "显示高级选项 "1，我们可以访问默认隐藏的更多高级配置设置。然后，RECONFIGURE 应用更改，使新设置生效。在执行某些操作（如启用用于执行系统命令的 xp_cmdshell）之前，通常需要执行这一步。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafH6VqrPCuic5vS8w0fian9nWZQCzz9JqHSpsCjkrxP0PWnrsMbNlH6ggsUvvLjwE7icJt5vhRtmATaw/640?wx_fmt=png&from=appmsg "")  
  
让我们再试一次：  
  
我又遇到了同样的错误。唯一的解决办法是  
  
```
SP_CONFIGURE "xp_cmdshell", 1
```  
  
  
此命令可启用 SQL Server 中的 xp_cmdshell 功能。默认情况下，出于安全考虑，该功能是禁用的，因为它允许在 SQL Server 环境中执行系统命令。通过设置 "xp_cmdshell "为 1，我们将指示 SQL Server 启用此功能。运行命令后，我们需要使用 RECONFIGURE 来应用更改。启用 xp_cmdshell 允许我们运行操作系统命令，这是在目标计算机上执行进一步操作的关键步骤。  
  
```
RECONFIGURE
```  
  
  
  
```
xp_cmdshell "whoami"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafH6VqrPCuic5vS8w0fian9nWpzMicfplAAyGxaTPWLnCm5kJr5QnfbjVbsTXwl4lmGBhsdb4aWueCOQ/640?wx_fmt=png&from=appmsg "")  
  
**终于成功了**  
  
**最终想法**  
  
配置调整到位后，攻击成功执行。通过启用高级选项和调整设置，我们能够使用 xp_cmdshell 在目标计算机上运行命令。这凸显了确保 SQL Server 配置安全的重要性，因为被忽视的设置很容易被利用。正确管理这些配置是防范此类漏洞的关键。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
