#  2024HVV-0801【0day】xxx狗输入法_逻辑绕过windows登录漏洞   
原创 病毒獵手 童杭波  oldhand   2024-08-01 23:44  
  
   
漏洞描述:   
  
通过xxx狗输入法的游戏中心，打开系统权限的内部指令，直接绕过win11  
权限验证登录。  
  
****## 一.漏洞复现1  
### 步骤1：锁屏界面切换输入法为xxx狗  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bA8WMKwicHvpfNSib7bDnd3QGHTXSyDib2TicQhQNNaiaxeKD2vE5m9dfyYdw/640?wx_fmt=png&from=appmsg "")  
  
### 步骤2：打开屏幕键盘  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bAnEic7bJD3n3qsf1bH4zkD6yt56Y4icEDVqkTnktYjf7pOKQn3BCke7cQ/640?wx_fmt=png&from=appmsg "")  
  
###  步骤3：挪动屏幕键盘，点击xxx狗输入法的头像   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bA3iaP4nS44zBWsmJWzMp6qDm6XLfeS2CB09Rk66DrUIMjS5rSAGJF4NQ/640?wx_fmt=png&from=appmsg "")  
  
### 步骤4：打开游戏中心  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bA4opTE9d3qyujeGMNUjvnNbvPOM9Ooh9QuCd1TWaLA5q2BUsEbIqMaQ/640?wx_fmt=png&from=appmsg "")  
  
### 步骤5：点击任意游戏下载  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bAabRZ805lSJyz6BZRHOnKRE6RCnOXq9vaVFlOUsia0h2MjsQ4kuIRDqQ/640?wx_fmt=png&from=appmsg "")  
  
### 步骤6：点击更改下载地址  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bALw4V3iaiblGXbEjKtl41VvVawa542CuNGJO1NbOouwUb00dyRcTYH9og/640?wx_fmt=png&from=appmsg "")  
  
  
步骤  
7  
：文  
件管理器路径栏输入  
C:\Windows\System32\cmd.exe  
，打开  
cmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bAiaXWECzHGqoONDic86Pibm7d2B37MkHQUiclvPnV6Nb0rItxz6fk2t5JQg/640?wx_fmt=png&from=appmsg "")  
  
  
步骤8  
：调用系统命令cmd   
创建登录账号  
  
net user oldhand   WIS-HUNTER@2022  /add  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bA0fyu0wuu8ib7WKYFSu81z90BgfOic0thvgukSpOzqk6S3rV2DypeEVOA/640?wx_fmt=png&from=appmsg "")  
  
### 步骤9：用系统命令查看所有用户  
### netuser   
### 步骤10：切换至新创建用户oldhand  
  
****  
****  
### 步骤11. 即可登录本机  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cy038mJgyib7hKuibPTG0ra2sL4xhvJ6bAWaJvHt88YXzTIibmvh5GicfiaYxbATEc3cg2V6O4zxeQFQ9vPbFlscRYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
视频链接：https://www.bilibili.com/video/BV1scvveXEtG  
  
