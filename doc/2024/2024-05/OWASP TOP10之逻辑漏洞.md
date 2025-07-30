#  OWASP TOP10之逻辑漏洞   
原创 TimeAxis Sec  TimeAxis Sec   2024-05-30 22:29  
  
### 点击蓝字关注我们  
# 什么是逻辑漏洞  
  
逻辑漏洞是指由于程序逻辑不严导致一些逻辑分支处理错误造成的漏洞  
  
在实际开发中，因为开发者水平不一没有安全意识，而且业务发展迅速内部测试没有及时到位，所以常常会出现类似的漏洞  
# 越权  
  
越权（或者说权限提升，Privilege Escalation）是指攻击者能够执行他本身没有资格执行的一些操作，属于“访问控制”的问题。用大白话讲，越权就是“超越了你你拥有的权限，干了你本来不可能干的事儿” 越权分为3种，水平越权，垂直越权和未授权访问  
## 水平越权  
  
如果攻击者能够执行与自己同级别的其他用户能够执行的操作，这就存在水平越权漏洞 可以理解为从用户A到用户B（用户A和用户B是同等级）  
## 垂直越权  
  
如果攻击者能够执行某项功能，而他所属的角色并不具备该权限，这就存在垂直越权漏洞 可以理解为从用户A到管理员（管理员比用户A等级高）  
## 未授权访问  
  
不用登录也可以访问  
## 越权的危害  
  
若存在水平越权，就可以看到其他用户的数据，进而会导致用户数据泄露，危害用户数据安全  
  
若存在垂直越权，就可以操作管理员账号权限的功能 例如，新建用户或删除用户等  
  
越权漏洞的危害与影响主要是与对应业务的重要性相关，比如说某一页面服务器端响应（不局限于页面返回的信息，有时信息在响应包中，页面不一定能看见）中返回登录名、登录密码、手机号、身份证等敏感信息，如果存在平行越权，通过对用户ID的遍历，就可以查看所有用户的敏感信息，这也是一种变相的脱库，而且很难被防火墙发现，因为这和正常的访问请求没有什么区别，也不会包含特殊字符，具有十足的隐秘性  
# 如何挖掘  
## 未使用cookie鉴权  
  
通过修改 userid 等字段进行越权  
  
常见方式便是通过全局搜索 userid、id、countid 等字符，通过修改对应 id 值进行判断  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxNVAmJSLuWPib8w0ndbmg9sRXrxgW6GOicGWfJDS1ic0pnA9z1Fic2oLiaq2A/640?wx_fmt=png&from=appmsg "")  
例如此处获取用户数据功能，如果未检测用户 id 是否与 cookie 对应。那么便可以通过枚举用户 id，获取其他用户数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxNw5zJE7uKLkyKE5rxOicTxmZPW1KYC0nFURRG8VrRdfcxeo9U0stkrDA/640?wx_fmt=png&from=appmsg "")  
## 使用cookie鉴权  
  
第一种：拥有两个账号密码的情况下，使用管理员账号操作，抓取数据包，修改 cookie 为普通用户的 cookie  
  
第二种：只有普通账号的情况下，通过 js 文件发现接口，通过自主访问接口，fuzz 字段值进行越权测试  
  
分别登录管理员账号和普通用户账号获取cookie  
  
使用管理员进行添加用户操作并抓取数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxNnP20iarUefrvOBFKqv64t2009jPUmTc7XLqdwibYdNXFhEumpDmq6BjA/640?wx_fmt=png&from=appmsg "")  
将数据包发送到Repeater模块，替换 cookie 为普通用户 cookie。如果依旧可以正常执行，那么即表示存在越权漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxNtxtjBwXGOdNB3yMRwErXEjsS8kGAKFMLtexCQO2ibhor5SXdedga5dQ/640?wx_fmt=png&from=appmsg "")  
  
只有普通用户账号  
  
一般会先通过 js 文件、swagger 等获取存在的接口，然后访问接口查看是否能直接获取信息。如果能够获取信息那么删除认证因子看看是否能够未授权  
  
如果直接访问提示错误，并且没有办法 fuzz 到具体的参数的话，一般就无法利用了。但是有些情况下，会提示缺少什么参数，或者什么参数不能为空 这就可以构造出具体的请求包进行测试了，如果能够进行操作，比如获取某用户信息，修改某用户数据，那么就存在越权漏洞  
  
使用普通账号登录后的 Cookie，构造更新数据的数据包，成功执行更新操作，即存在越权漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxNcqlbDJVQsUnjiczjWXfsC88dricFic3Mbt5KjYde4veickV2VYgk8n19bg/640?wx_fmt=png&from=appmsg "")  
当提示无权限或者其他错误信息，即不存在越权漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxN6au6znuL4u8LIOc30jRQEkwcIRHV9D9RujGHAjE8riaI6tIiaZ0gXKEg/640?wx_fmt=png&from=appmsg "")  
# 业务逻辑  
## 账户  
  
注册（覆盖注册，批量用户注册等）  
  
密码（任意密码修改等）  
  
用户名（用户名枚举）  
  
短信（短信轰炸等）  
  
登录（策略绕过等）  
  
申诉（身份伪造，逻辑绕过等）  
  
信息查询（越权，遍历等）  
  
验证码复用（任意用户登录，任意用户注册等）  
  
JWT凭证复用（伪造用户凭证）  
  
Session（Session泄露等）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwRZOx8ichfGO47CzJAtWBsxNkN96Kf40mESPd0ZH4mx45D75mwbZsaCicUtjCg13icrQ1D6uZMgNt44w/640?wx_fmt=png&from=appmsg "")  
  
点点关注不迷路~  
  
  
