> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247573744&idx=1&sn=2fbda2cb0c158165d05929d821e9927e

#  windows内网渗透-常用命令集合  
点击关注👉  马哥网络安全   2025-07-01 09:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAk1nlByTOFiahZKGHekfZGC180aw53rHwCE1KXCFEyHULHRFVH3sTdiaibVFgTPic4UWScria3Vocb1TyQ/640?wx_fmt=png&from=appmsg "")  
  
# 0x01 常用信息收集命令  
## 0x01.1 管理用户  
### 0x01.1.1 查看本机上的用户帐号列表  

```
命令: net user
```


```
# 执行结果:

C:\Users\Administrator>net user

\\SRV-WEB-KIT 的用户帐户

-------------------------------------------------------------------------------
Administrator            Guest                    testuser
命令成功完成。
```

### 0x01.1.2 查看某个用户详情  

```
net user [用户名]
```


```
# 例子:
# 查看 Administrator 用户详情
命令: net user Administrator

# 执行结果
C:\Users\Administrator>net user Administrator
用户名                 Administrator
全名
注释                   管理计算机(域)的内置帐户
用户的注释
国家/地区代码           000 (系统默认值)
帐户启用               Yes
帐户到期               从不

上次设置密码            2019/5/25 17:34:38
密码到期               2019/7/6 17:34:38
密码可更改              2019/5/26 17:34:38
需要密码               Yes
用户可以更改密码         Yes

允许的工作站            All
登录脚本
用户配置文件
主目录
上次登录               2021/1/31 17:01:25

可允许的登录小时数       All

本地组成员             *Administrators       *HelpLibraryUpdaters
全局组成员             *None
命令成功完成。
```

### 0x01.1.3 查看本机上的在线用户  

```
命令: quser
```


```
# 执行结果:

C:\Users\Administrator>quser
 用户名                会话名             ID  状态    空闲时间   登录时间
>administrator       console            1  运行中     无    2021/1/29 14:54
```

### 0x01.1.4 添加本机用户  

```
# 需要当前登录用户拥有管理组的权限

命令: net user [要创建的用户名] [密码] /add
# 例子: 
# 创建个 testuser用户 密码为zaq123456789!

命令: net user testuser zaq123456789! /add
```


```
# 执行结果:

C:\Users\Administrator>net user testuser zaq123456789! /add
命令成功完成。
```

### 0x01.1.5 修改本机用户密码  

```
# 需要当前登录用户拥有管理组的权限
# 注意: 如果要设置为空密码 密码处就写 &#34;&#34;

命令: net user [要修改的账号] [要设置的新密码]
# 例子-1: 
# 修改 testuser用户 密码为zaq111!
命令: net user testuser zaq111!

# 例子-2: 
# 修改 testuser用户 密码为空
命令: net user testuser &#34;&#34;
```


```
# 执行结果:

C:\Users\Administrator>net user testuser zaq111!
命令成功完成。
```

### 0x01.1.6 删除本机用户  

```
# 需要当前登录用户拥有管理组的权限

命令: net user [要删除的账号] /del
# 例子-1: 
# 删除 testuser用户

命令: net user testuser /del
```


```
# 执行结果:

C:\Users\Administrator>net user testuser /del
命令成功完成。
```

## 0x01.2 管理本地用户组  
### 0x01.2.1 査看本地用户组的名称  

```
# 执行完毕即可查看当前系统中所有的用户组

命令: Net Localgroup
```


```
# 执行结果:

C:\Users\Administrator>Net Localgroup

\\SRV-WEB-KIT 的别名

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*HelpLibraryUpdaters
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*SQLServer2005SQLBrowserUser$SRV-WEB-KIT
*SQLServerMSASUser$SRV-WEB-KIT$MSSQLSERVER
*Users
*WinRMRemoteWMIUsers__
*WSS_ADMIN_WPG
*WSS_WPG
命令成功完成。
```

### 0x01.2.2 查看某个用户组中的成员  

```
# 执行完毕以后即可显示某个组下面所有的成员
命令: Net Localgroup Administrators
```


```
# 执行结果:

C:\Users\Administrator>Net Localgroup Administrators
别名     Administrators
注释     管理员对计算机/域有不受限制的完全访问权

成员

-------------------------------------------------------------------------------
Administrator
testuser
命令成功完成。
```

### 0x01.2.3 添加用户组的成员  

```
# 需要当前登录用户拥有管理组的权限

命令: net localgroup [用户组名称] [要添加的账号] /add
# 例子: 
# 把 testuser用户 添加进入 administrators 组
命令: net localgroup administrators testuser /add
```


```
# 执行结果:

C:\Users\Administrator>net localgroup administrators testuser /add
命令成功完成。
```

### 0x01.2.4 删除用户组的成员  

```
# 需要当前登录用户拥有管理组的权限

命令: net localgroup [用户组名称] [要删除的账号] /delete
# 例子: 
# 把 testuser用户 移出 administrators 组
命令: net localgroup administrators testuser /delete
```


```
# 执行结果:

C:\Users\Administrator>net localgroup administrators testuser /delete
命令成功完成。
```

## 0x01.3 whoami-常用命令参数  

```
# 显示当前登录到本地系统的用户的用户、 组和权限信息。 
# 如果不使用参数, whoami将显示当前域和用户的名称。
```

  
           
  
<table><thead><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">whoami参数说明</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><br/></span></section></td></tr></thead><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">参数</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">说明</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/?</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">显示该命令帮助消息</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/all</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">显示当前用户名、所属的组以及安全等级当前用户访问令牌的标识符(SID)、声明和权限</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/upn</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">用用户主体 (User Principal) 格式显示</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/fqdn</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">用完全合格的 (Fully Qualified) 格式显示用户名</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/logonid</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">显示当前用户的登录 ID</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/user</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">显示当前用户的信息以及安全标识符 (SID)</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/groups</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">显示当前用户的组成员信息、帐户类型和安全标识符 (SID) 和属性。</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/priv</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0.25em 0.5em;outline: 0px;overflow-wrap: break-word !important;word-break: keep-all;hyphens: auto;border: 1px solid rgb(223, 223, 223);max-width: 100%;box-sizing: border-box !important;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(63, 63, 63);"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">显示当前用户的安全特权</span></section></td></tr></tbody></table>  

```
# 例子1-查看本地系统的用户的用户:
命令: whoami

# 返回结果
rookit\sqladmin

&#34;\&#34;前面的是域名 
&#34;\&#34;后面的是登录账户
```


```
# 例子2-显示当前用户的登录ID:
命令: whoami /logonid

# 返回结果
S-1-5-5-0-302326
```

## 0x01.4 查看机器名  

```
命令: hostname
```


```
# 执行结果:

C:\Users\Administrator>hostname
Srv-Web-Kit
```

## 0x01.5 查看系统信息  

```
# 可以通过这个命令查看打的补丁,然后比对出没有打的补丁,进行攻击

命令: systeminfo
```


```
# 执行结果:

C:\Users\Administrator>systeminfo
主机名:           SRV-WEB-KIT
OS 名称:          Microsoft Windows Server 2012 R2 Datacenter
OS 版本:          6.3.9600 暂缺 Build 9600
OS 制造商:        Microsoft Corporation
OS 配置:          成员服务器
OS 构件类型:      Multiprocessor Free
注册的所有人:     Windows 用户
注册的组织:       
产品 ID:          00253-50000-00000-AA442
初始安装日期:     2019/5/25, 17:34:42
系统启动时间:     2021/1/29, 14:51:18
系统制造商:       VMware, Inc.
系统型号:         VMware Virtual Platform
系统类型:         x64-based PC
处理器:        安装了 2 个处理器。
               [01]: Intel64 Family 6 Model 126 Stepping 5 GenuineIntel ~2305 Mhz
               [02]: Intel64 Family 6 Model 126 Stepping 5 GenuineIntel ~2305 Mhz
BIOS 版本:        Phoenix Technologies LTD 6.00, 2020/2/27
Windows 目录:     C:\Windows
系统目录:         C:\Windows\system32
启动设备:         \Device\HarddiskVolume1
系统区域设置:     zh-cn;中文(中国)
输入法区域设置:   zh-cn;中文(中国)
时区:             (UTC+08:00)北京，重庆，香港特别行政区，乌鲁木齐
物理内存总量:     2,047 MB
可用的物理内存:   1,066 MB
虚拟内存: 最大值: 2,431 MB
虚拟内存: 可用:   1,377 MB
虚拟内存: 使用中: 1,054 MB
页面文件位置:     C:\pagefile.sys
域:               rootkit.org
登录服务器:       \\SRV-WEB-KIT
修补程序:         安装了 31 个修补程序。
                  [01]: KB2959936
                  [02]: KB2896496
                  [03]: KB2919355
                  [04]: KB2920189
                  [05]: KB2928120
                  [06]: KB2931358
                  [07]: KB2931366
                  [08]: KB2933826
                  [09]: KB2938772
                  [10]: KB2949621
                  [11]: KB2954879
                  [12]: KB2958262
                  [13]: KB2958263
                  [14]: KB2961072
                  [15]: KB2965500
                  [16]: KB2966407
                  [17]: KB2967917
                  [18]: KB2971203
                  [19]: KB2971850
                  [20]: KB2973351
                  [21]: KB2973448
                  [22]: KB2975061
                  [23]: KB2976627
                  [24]: KB2977629
                  [25]: KB2981580
                  [26]: KB2987107
                  [27]: KB2989647
                  [28]: KB2998527
                  [29]: KB3000850
                  [30]: KB3003057
                  [31]: KB3014442
网卡:             安装了 1 个 NIC。
                  [01]: Intel(R) 82574L 千兆网络连接
                      连接名:      Ethernet0
                      启用 DHCP:   否
                      IP 地址
                        [01]: 192.168.3.73
                        [02]: fe80::1d9:9482:6cd:6ea2
Hyper-V 要求:     已检测到虚拟机监控程序。将不显示 Hyper-V 所需的功能。
```

## 0x01.6 查看系统版本号  

```
命令: ver
```


```
# 执行结果:

C:\Users\Administrator>ver
Microsoft Windows [版本 6.3.9600]
```

## 0x01.7 查看当前操作系统版本信息  

```
命令: wmic os get caption,csdversion,osarchitecture,version
```


```
# 执行结果:

C:\Users\Administrator>wmic OS get Caption,CSDVersion,OSArchitecture,Version
Caption                                      CSDVersion  OSArchitecture  Version   
Microsoft Windows Server 2012 R2 Datacenter              64 位           6.3.9600  
```

## 0x01.8 检查当前shell权限  

```
命令: whoami /user
```


```
# 执行结果:

C:\Users\Administrator>whoami /user

用户信息
----------------

用户名                    SID
========================= ===========================================
srv-web-kit\administrator S-1-5-21-202412995-3582062751-167045153-500
```

## 0x01.9 tcp/udp 网络连接状态信息  

```
# 可以通过该命令查看本机服务开放端口
# 
# 例如:
#        关系型数据库
#       3306  MySQL
#            1521    Oracle
#            1433    SqlServer
#        
#        非关系型数据库
#            6379    Redis
#            27017    MongoDB
#            11211    memcached

命令: netstat -ano
```


```
# 执行结果:

C:\Users\Administrator>netstat -ano

活动连接

  协议    本地地址                外部地址                 状态             PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:81             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       440
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       816
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       544
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       1132
  TCP    0.0.0.0:49186          0.0.0.0:0              LISTENING       536
  TCP    0.0.0.0:49192          0.0.0.0:0              LISTENING       1952
  TCP    0.0.0.0:49213          0.0.0.0:0              LISTENING       544
  TCP    192.168.3.73:139       0.0.0.0:0              LISTENING       4
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:81                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       660
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       440
  TCP    [::]:49153             [::]:0                 LISTENING       816
  TCP    [::]:49154             [::]:0                 LISTENING       840
  TCP    [::]:49155             [::]:0                 LISTENING       544
  TCP    [::]:49156             [::]:0                 LISTENING       1132
  TCP    [::]:49186             [::]:0                 LISTENING       536
  TCP    [::]:49192             [::]:0                 LISTENING       1952
  TCP    [::]:49213             [::]:0                 LISTENING       544
  UDP    0.0.0.0:123            *:*                                    912
  UDP    0.0.0.0:500            *:*                                    840
  UDP    0.0.0.0:4500           *:*                                    840
  UDP    0.0.0.0:5355           *:*                                    984
  UDP    127.0.0.1:51594        *:*                                    544
  UDP    127.0.0.1:61031        *:*                                    2296
  UDP    127.0.0.1:65247        *:*                                    840
  UDP    127.0.0.1:65248        *:*                                    984
  UDP    192.168.3.73:137       *:*                                    4
  UDP    192.168.3.73:138       *:*                                    4
  UDP    [::]:123               *:*                                    912
  UDP    [::]:500               *:*                                    840
  UDP    [::]:4500              *:*                                    840
  UDP    [::]:5355              *:*                                    984
  UDP    [fe80::1d9:9482:6cd:6ea2%12]:546  *:*                         816
```

## 0x01.10 查看安装的应用程序及版本信息  

```
命令: wmic product get name,version
```


```
# 执行结果:

Name                                                            Version          
Microsoft DCF MUI (Chinese (Simplified)) 2013                   15.0.4420.1017   
Microsoft Office Professional Plus 2013                         15.0.4420.1017   
Microsoft OneNote MUI (Chinese (Simplified)) 2013               15.0.4420.1017   
Microsoft Office OSM MUI (Chinese (Simplified)) 2013            15.0.4420.1017   
Microsoft Office OSM UX MUI (Chinese (Simplified)) 2013         15.0.4420.1017   
Microsoft InfoPath MUI (Chinese (Simplified)) 2013              15.0.4420.1017   
Microsoft Access MUI (Chinese (Simplified)) 2013                15.0.4420.1017   
Microsoft Excel MUI (Chinese (Simplified)) 2013                 15.0.4420.1017   
Microsoft PowerPoint MUI (Chinese (Simplified)) 2013            15.0.4420.1017   
Microsoft Publisher MUI (Chinese (Simplified)) 2013             15.0.4420.1017   
Microsoft Outlook MUI (Chinese (Simplified)) 2013               15.0.4420.1017   
Microsoft Office 64-bit Components 2013                         15.0.4420.1017   
Microsoft Office Shared 64-bit MUI (Chinese (Simplified)) 2013  15.0.4420.1017   
Microsoft Groove MUI (Chinese (Simplified)) 2013                15.0.4420.1017   
Microsoft Word MUI (Chinese (Simplified)) 2013                  15.0.4420.1017   
Microsoft Lync MUI (Chinese (Simplified)) 2013                  15.0.4420.1017   
Microsoft Office Proofing (Chinese (Simplified)) 2013           15.0.4420.1017   
Microsoft Office Shared MUI (Chinese (Simplified)) 2013         15.0.4420.1017   
Microsoft Office 校对工具 2013 - 简体中文                          15.0.4420.1017   
Microsoft Office Proofing Tools 2013 - English                  15.0.4420.1017   
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508     14.20.27508      
                                                                                 
Python 3.8.3 Test Suite (32-bit)                                3.8.3150.0       
Python 3.7.7 Core Interpreter (64-bit)                          3.7.7150.0       
Python 3.8.3 Tcl/Tk Support (32-bit)                            3.8.3150.0       
Python 3.7.7 Add to Path (64-bit)                               3.7.7150.0       
Python 3.8.3 Utility Scripts (32-bit)                           3.8.3150.0       
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.20.27508     14.20.27508      
Java 8 Update 241 (64-bit)                                      8.0.2410.7       
Java SE Development Kit 8 Update 241 (64-bit)                   8.0.2410.7       
Python 3.7.7 Documentation (64-bit)                             3.7.7150.0       
Python 3.7.7 Standard Library (64-bit)                          3.7.7150.0       
Python 3.7.7 Test Suite (64-bit)                                3.7.7150.0       
Python 2.7.14 (64-bit)                                          2.7.14150        
Python 3.8.3 Core Interpreter (32-bit)                          3.8.3150.0       
Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.21005   12.0.21005       
Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729       9.0.30729        
Xftp 6                                                          6.0.0201         
Python 3.7.7 pip Bootstrap (64-bit)                             3.7.7150.0       
Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.21005      12.0.21005       
Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030   11.0.61030       
Python 3.7.7 Executables (64-bit)                               3.7.7150.0       
Python 3.8.3 Add to Path (32-bit)                               3.8.3150.0       
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508  14.20.27508      
Xshell 6                                                        6.0.0206         
Python 3.8.3 Executables (32-bit)                               3.8.3150.0       
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.20.27508  14.20.27508      
Python 3.7.7 Utility Scripts (64-bit)                           3.7.7150.0       
Python 3.8.3 Development Libraries (32-bit)                     3.8.3150.0       
Microsoft Visual C++ 2012 x86 Additional Runtime - 11.0.61030   11.0.61030       
Microsoft Visual C++ 2010  x64 Redistributable - 10.0.30319     10.0.30319       
Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030      11.0.61030       
Python 3.7.7 Tcl/Tk Support (64-bit)                            3.7.7150.0       
Python 3.8.3 Standard Library (32-bit)                          3.8.3150.0       
Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.17    9.0.30729        
Python 3.8.3 pip Bootstrap (32-bit)                             3.8.3150.0       
Python 3.7.7 Development Libraries (64-bit)                     3.7.7150.0       
Microsoft Visual C++ 2012 x86 Minimum Runtime - 11.0.61030      11.0.61030       
VMware Tools                                                    11.0.0.14549434  
Python 3.8.3 Documentation (32-bit)                             3.8.3150.0       
Python Launcher                                                 3.8.7072.0       
Java Auto Updater                                               2.8.241.7        
```

## 0x01.11 查询杀软  

```
命令: WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
```


```
# 执行结果:

C:\Users\miao>WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List

displayName=Windows Defender
displayName=火绒安全软件
```

## 0x01.12 查看网络配置  

```
命令: ipconfig /all
```


```
# 执行结果:

C:\Users\miao>ipconfig /all

Windows IP 配置

   主机名  . . . . . . . . . . . . . : Srv-Web-Kit
   主 DNS 后缀 . . . . . . . . . . . : rootkit.org
   节点类型  . . . . . . . . . . . . : 混合
   IP 路由已启用 . . . . . . . . . . : 否
   WINS 代理已启用 . . . . . . . . . : 否
   DNS 后缀搜索列表  . . . . . . . . : rootkit.org

以太网适配器 Ethernet0:

   连接特定的 DNS 后缀 . . . . . . . : 
   描述. . . . . . . . . . . . . . . : Intel(R) 82574L 千兆网络连接
   物理地址. . . . . . . . . . . . . : 00-0C-29-ED-69-2C
   DHCP 已启用 . . . . . . . . . . . : 否
   自动配置已启用. . . . . . . . . . : 是
   本地链接 IPv6 地址. . . . . . . . : fe80::1d9:9482:6cd:6ea2%12(首选) 
   IPv4 地址 . . . . . . . . . . . . : 192.168.3.73(首选) 
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.3.1
   DHCPv6 IAID . . . . . . . . . . . : 301993001
   DHCPv6 客户端 DUID  . . . . . . . : 00-01-00-01-27-A4-35-79-00-0C-29-ED-69-2C
   DNS 服务器  . . . . . . . . . . . : 192.168.3.144
                                       8.8.8.8
   TCPIP 上的 NetBIOS  . . . . . . . : 已启用

隧道适配器 isatap.{0E1BD827-CF77-4F85-8B1D-ECD8D053952F}:

   媒体状态  . . . . . . . . . . . . : 媒体已断开
   连接特定的 DNS 后缀 . . . . . . . : 
   描述. . . . . . . . . . . . . . . : Microsoft ISATAP Adapter
   物理地址. . . . . . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP 已启用 . . . . . . . . . . . : 否
   自动配置已启用. . . . . . . . . . : 是
```

## 0x01.13 查看进程  

```
命令: tasklist /v
```


```
# 执行结果:


映像名称                    PID    会话名     会话   内存使用   状态        用户名                          CPU 时间      窗口标题                    
======================== ====== ========== ===== ========= ========= ============================== ============ ==========
System Idle Process        0     Services    0        4 K   Unknown   NT AUTHORITY\SYSTEM            14:02:41     暂缺  
System                     4     Services    0      296 K   Unknown   暂缺                            0:00:58      暂缺  
smss.exe                   232   Services    0      916 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
csrss.exe                  360   Services    0    4,760 K   Unknown   NT AUTHORITY\SYSTEM            0:00:01      暂缺  
wininit.exe                440   Services    0    4,076 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
csrss.exe                  448   Console     1   40,040 K   Running   NT AUTHORITY\SYSTEM            0:00:04      暂缺  
winlogon.exe               492   Console     1    6,888 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
services.exe               536   Services    0    6,096 K   Unknown   NT AUTHORITY\SYSTEM            0:00:01      暂缺  
lsass.exe                  544   Services    0   13,428 K   Unknown   NT AUTHORITY\SYSTEM            0:00:07      暂缺  
svchost.exe                616   Services    0   10,256 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
svchost.exe                660   Services    0    7,124 K   Unknown   NT AUTHORITY\NETWORK SERVICE   0:00:00      暂缺  
dwm.exe                    760   Console     1   99,548 K   Running   Window Manager\DWM-1           0:00:04      DWM Notification Window     
vmacthlp.exe               768   Services    0    4,144 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
svchost.exe                816   Services    0   15,180 K   Unknown   NT AUTHORITY\LOCAL SERVICE     0:00:07      暂缺  
svchost.exe                840   Services    0   33,636 K   Unknown   NT AUTHORITY\SYSTEM            0:00:15      暂缺  
svchost.exe                912   Services    0   13,024 K   Unknown   NT AUTHORITY\LOCAL SERVICE     0:00:00      暂缺  
svchost.exe                984   Services    0   16,676 K   Unknown   NT AUTHORITY\NETWORK SERVICE   0:00:00      暂缺  
svchost.exe                584   Services    0    9,216 K   Unknown   NT AUTHORITY\LOCAL SERVICE     0:00:00      暂缺  
spoolsv.exe                1132  Services    0   14,608 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
svchost.exe                1160  Services    0    8,020 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
inetinfo.exe               1180  Services    0   14,740 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
sqlwriter.exe              1324  Services    0    5,852 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
svchost.exe                1344  Services    0   10,692 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
VGAuthService.exe          1368  Services    0   10,684 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
vmtoolsd.exe               1404  Services    0   20,432 K   Unknown   NT AUTHORITY\SYSTEM            0:00:05      暂缺  
ManagementAgentHost.exe    1420  Services    0    9,824 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
svchost.exe                1436  Services    0    9,064 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
svchost.exe                1836  Services    0    9,852 K   Unknown   NT AUTHORITY\NETWORK SERVICE   0:00:00      暂缺  
svchost.exe                1952  Services    0    4,664 K   Unknown   NT AUTHORITY\NETWORK SERVICE   0:00:00      暂缺  
TPAutoConnSvc.exe          1116  Services    0    7,724 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
dllhost.exe                2148  Services    0   11,076 K   Unknown   NT AUTHORITY\SYSTEM            0:00:00      暂缺  
msdtc.exe                  2224  Services    0    7,136 K   Unknown   NT AUTHORITY\NETWORK SERVICE   0:00:00      暂缺  
WmiPrvSE.exe               2376  Services    0   19,044 K   Unknown   NT AUTHORITY\NETWORK SERVICE   0:00:14      暂缺  
WmiPrvSE.exe               2588  Services    0   25,652 K   Unknown   NT AUTHORITY\SYSTEM            0:00:21      暂缺  
TPAutoConnect.exe          1316  Console     1    9,116 K   Running   SRV-WEB-KIT\Administrator      0:00:00      HiddenTPAutoConnectWindow   
conhost.exe                2372  Console     1    3,344 K   Unknown   SRV-WEB-KIT\Administrator      0:00:00      暂缺  
taskhostex.exe             716   Console     1    9,836 K   Running   SRV-WEB-KIT\Administrator      0:00:00      Task Host Window            
ChsIME.exe                 2804  Console     1   14,968 K   Running   SRV-WEB-KIT\Administrator      0:00:00      暂缺  
explorer.exe               572   Console     1  102,592 K   Running   SRV-WEB-KIT\Administrator      0:00:13      暂缺  
ServerManager.exe          2460  Console     1   65,516 K   Running   SRV-WEB-KIT\Administrator      0:00:06      服务器管理器                
vmtoolsd.exe               960   Console     1   27,372 K   Running   SRV-WEB-KIT\Administrator      0:00:07      暂缺  
ReportingServicesService.  2296  Services    0  137,956 K   Unknown   ROOTKIT\dbadmin                0:00:03      暂缺  
cmd.exe                    128   Console     1    2,696 K   Running   SRV-WEB-KIT\Administrator      0:00:00      管理员: C:\Windows\system32\cmd.exe - tasklist  /v
conhost.exe                2392  Console     1   10,076 K   Running   SRV-WEB-KIT\Administrator      0:00:09      CicMarshalWnd               
tasklist.exe               752   Console     1    6,460 K   Unknown   SRV-WEB-KIT\Administrator      0:00:00      暂缺  
```

## 0x01.14 远程桌面连接历史记录  

```
命令: cmdkey /l
```


```
# 执行结果:

C:\Users\miao>cmdkey /l

当前保存的凭据:

    目标: WindowsLive:target=virtualapp/didlogical
    类型: 普通
    用户: 02qsioqmstvj
    本地机器持续时间
```

## 0x01.15 远程桌面连接  

```
命令: mstsc
```

## 0x01.16 远程桌面3389端口开启  

```
# 注意: 执行命令的用户需要可以操作注册表的权限
# 注意如果这条命令执行完毕还是不能连接3389那就试试下面的那条命令

命令: REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal&#34; &#34;Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
# 注意: 执行命令的用户需要可以操作注册表的权限
# 有的时候开了3389也不一定可以连接那就试试执行该命令解除访问限制

命令1: net stop mpssvc

命令2: reg add &#34;HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp&#34; /v SecurityLayer /t REG_DWORD /d 0  /f & reg add &#34;HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp&#34; /v UserAuthentication /t REG_DWORD /d 0 /f  & reg add &#34;HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp&#34; /v fAllowSecProtocolNegotiation /t REG_DWORD /d 0 /f
```

## 0x01.17 关闭防火墙  

```
# 由于目标防火墙（windows firewall）可能会对我们的操作有影响，我们直接使用命令给他关掉：
命令: Netsh advfirewall set allprofiles state off
```

## 0x01.18 远程桌面3389端口关闭  

```
# 注意: 执行命令的用户需要可以操作注册表的权限

命令: REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal&#34; &#34;Server /v fDenyTSConnections /t REG_DWORD /d 11111111 /f
```

# 0x02 域常用命令  
## 0x02.1 查看当前登录域  

```
命令: net config workstation
```

## 0x02.2 管理域用户  
### 0x02.2.1 查看域的用户帐号列表  

```
命令: net user /domain
```

### 0x02.2.2 查看某个域用户详情  

```
net user [域用户名] /domain
```

### 0x02.2.3 添加域用户  

```
命令: net user [要创建的域用户名] [密码] /add /domain
# 例子: 
# 创建个 testuser用户 密码为zaq123456789!

命令: net user testuser zaq123456789! /add /domain
```

### 0x02.2.4 修改域用户密码  

```
# 需要当前登录用户拥有管理组的权限
# 注意: 如果要设置为空密码 密码处就写 &#34;&#34;

命令: net user /domain [要修改的账号] [要设置的新密码]
# 例子-1: 
# 修改 testuser用户 密码为zaq111!
命令: net user testuser zaq111!

# 例子-2: 
# 修改 testuse /domain testuser &#34;&#34;
```

### 0x02.2.5 删除域用户  

```
# 需要当前登录用户拥有管理组的权限

命令: net user [要删除的账号] /del /domain
# 例子-1: 
# 删除 testuser用户

命令: net user testuser /del /domain
```

## 0x02.3 查询域控主机名  

```
命令: nltest /dsgetdc:[域名]
```

## 0x02.4 列出域之间的信任关系  

```
命令: nltest /domain_trusts
```

## 0x02.5 查看所有域控  

```
命令: net group &#34;domain controllers&#34; /domain
```

## 0x02.6 查询域列表  

```
命令: net view /domain
```

## 0x02.7 判断主域  

```
# 判断主域, 个个都说主域会做时间服务器所以记录一下
命令: net time /domain
```

## 0x02.8 查看当前会话  

```
命令: net session
```

## 0x02.9 查询某个ip的共享  

```
命令: net view \\[ip]
```

## 0x02.10 查询同域的机器  

```
命令: net view
```

## 0x02.11 查询域密码策略  

```
命令: net accounts /domain
```

## 0x02.12 查看域里的计算机  

```
命令: dsquery computer
```

## 0x02.13 查看域里的联系人  

```
命令: dsquery contact
```

## 0x02.14 查看域里的用户组  

```
命令: dsquery group
```

## 0x02.15 查看域用户  

```
命令: dsquery user
```

## 0x02.16 查看网段的划分  

```
命令: dsquery subnet
```

## 0x02.17 显示所有域控  

```
命令: dsquery server
```

## 0x02.18 查看域里的子网  

```
命令: dsquery subnet
```

# 0x03 总结  
  
自己老是记不住,所以就把常用的命令列举了出来,这样渗透的时候直接复制过去就可以了，建议收藏一下~  
  
内容转自Z0安全，如有侵权请联系删除  
  
# 阅读福利  
  
  
Linux命令是Linux系统正常运行的核心，也往往是初学者的瓶颈，这里整理了几份Linux命令教程，包括详细解读和命令示例，十分清晰明了。  
- 570个Linux命令大全  
  
- Linux命令大全（完整版）  
  
- Linux命令文档，看着一本就行了  
  
- Linux命令详解词典  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAmicHxVdj7ib1FjypsOnQKQesOCFs9o9x87E8xD5staTff873M20biabKZMbw0sXcutibiaN7964Of78fg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/UkV8WB2qYAmicHxVdj7ib1FjypsOnQKQesjb0jNZtqaibLcOHawhY6IrlicAMw1a2GdGYGFNA544tTFkic2UrSHKVYg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkAW0y5Fia92TvJrl4VSP3uoIhPqJhS7yWUicibyLibS9CQNunYAibVDrAGCDBQp3O4sEIZW22pNJIbqHw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  

```
 领取方式如下：扫描上方二维码添加时备注【Linu命令合集】即可100%免费领取请务必备注，不备注不发资料哦！
```

  
  
