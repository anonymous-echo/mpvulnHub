#  一次从注册功能隐藏到发现的sql注入漏洞   
lo2us  实战安全研究   2025-05-01 02:02  
  
# 1.访问站点  
  
  
打开burpsuite，配置代理等完成一系列抓取流量的配置操作后，开始访问目标系统  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIHoPshkdPws93K0JjLVAeKwSAU54aOop6XYPEpD32937BvzFd5U0iaiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
发现只有一个登录框。  
  
  
我们随便输入账号密码，点击登录，观察请求包和响应包  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLICYbtmhj9EXicSGicEvH5ehbq2QkrBIDY2MN1GCTpfQ5n3hAxaXmMqAVQ/640?wx_fmt=png&from=appmsg "")  
  
  
发现提示账号不存在（其实一个小漏洞，用户名遍历已到手）。  
  
  
注意此时我们的路径是/dev-api/auth/login。  
  
# 2.注册接口猜测  
  
  
根据我们登录接口，猜测一下注册接口是在/dev-api/auth/register。  
  
  
如何验证猜测，使用浏览器打开站点，F12打开开发者工具，全局搜索**/register**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIoPpa5na2Aft0FSaxsmmddyxabFZQ8wudQkIIiaiaZq50v9bgclOh89tA/640?wx_fmt=png&from=appmsg "")  
  
  
发现确实存在/auth/register。  
  
  
按照相同的格式和搜索方法，我们再搜索一下/auth/login。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIhdKN0lXut8ibsVj2Y8GuXx0qDRQPiaj2PeDdpibMDIm5M8PiaYIP88PMPA/640?wx_fmt=png&from=appmsg "")  
  
  
发现就在旁边。  
  
  
接着在burpsuite修改接口访问路径，尝试访问注册接口：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIXEplHnDyicamoqceD7qbn15t8QeVaQO6B8ZcqtMcicu1LqSRImxxWujQ/640?wx_fmt=png&from=appmsg "")  
  
  
成功！响应码返回200（可能是restful api规定的一个统一响应），并且响应体里显示服务器内部错误500并提示**当前系统没有开启注册功能**  
。  
  
  
接下来我们修改username、password的长度，发现皆有提示为：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLInibA05LPZjZoSJJwtdgsUsnI3qSHVwls9ibEm2UbEQLLL1xcqSqQnjiaA/640?wx_fmt=png&from=appmsg "")  
  
  
账户长度必须在2到20个字符之间。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLI9YWK1bQKeEYARRq4SCWrsP7RC4TJJ0N9UiboUGLR1MotV7vd23bfVicQ/640?wx_fmt=png&from=appmsg "")  
  
  
用户密码长度必须在5到20个字符之间。  
  
  
于是我们可以确认，注册接口是存活的，但是注册功能没有开启，因为我们的请求体的数据，确实后端处理，并返回给我们结果。  
  
# 3.注册接口sql注入  
  
  
此时其实可以大胆猜测，前面我的login处无法进行sql注入，因为后端可能重点关注的是用户名和密码并做了强过滤，很难找到注入点。  
  
  
但是，注册接口已经被禁止了，并且提示是**当前系统没有开启注册功能**  
，可以得到的结论是，我们的请求体一定发送到了后端，那么后端有以下2种逻辑：  
  
  
1. 先将请求体传递给服务器处理，创建账号并存入数据库，**检查**  
是否开启注册功能，如果没有开启，则账号不启用，并返回没有开启注册功能。  
  
1. 先将请求体传递给服务器处理，先**检查**  
是否开启了注册功能，如果没有开启，直接弃用并返回没有开启注册功能。  
  
注意，以上都涉及到了**检查**  
操作，如果是第一种情况，那么我们的请求体，肯定也会被sql语句加载进数据库进行查询，比如是否重复注册、符合规范等等。  
  
  
如果是第二种情况，数据库里可能有表项是用于设置是否开放注册的，比如register:value，value可能是0或1，也可能是false或true。  
  
  
接下来，构造请求包  
  
```
{"tenantId":"'","username":"1sssss","password":"sdsdawdssx.","rememberMe":true,"clientId":"e5cd7e4891bf95d1d19206ce24a7b32e","grantType":"password"}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIANKUib1xxzWeUSLgwAkhd0pe586buicibc9yGOicx84xDw9LVZ9F0fvOMA/640?wx_fmt=png&from=appmsg "")  
  
  
提示报错，很明显的报错注入，并且sql语句为：  
  
```
SQL: SELECT config_id, config_name, config_key, config_value, config_type, remark, tenant_id, create_dept, create_by, create_time, update_by, update_time FROM sys_config WHERE (config_key = ?) AND tenant_id = '''
```  
  
发现共有12列，开始使用union尝试找出数据库名  
  
  
payload：  
  
```
{"tenantId":"'UNION SELECT 1,2,3,4,5,6,7,8,9,database(),11,12 -- -","username":"1sssss","password":"sdsdawdssx.","rememberMe":true,"clientId":"e5cd7e4891bf95d1d19206ce24a7b32e","grantType":"password"}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIMRrmerMciaAlJcJnreGWCNJcn9Ec0yJSmibTr6WvmPbSPynvEmngZ50A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
得到root@localhost，成功注入。  
  
  
接下来就是保存请求到本地，使用sqlmap一把梭  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF12NfUCpL3vicKHamLbBFWLIe9vMsGwEdKcr6fECWqsTQLoiby6icuezwNWeyzZUBTCYOXPQHIyvZv3w/640?wx_fmt=png&from=appmsg "")  
  
# 收获  
  
  
1.有时隐藏的、功能关闭的接口，未必是**无法访问**  
的，并且我们可以在请求体里fuzz多测试一些payload等。  
  
```
作者：lo2us
原文链接：https://xz.aliyun.com/news/17055
```  
  
  
  
