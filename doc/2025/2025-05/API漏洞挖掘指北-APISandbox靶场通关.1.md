#  API漏洞挖掘指北-APISandbox靶场通关.1   
原创 摆烂的beizeng  土拨鼠的安全屋   2025-05-06 03:33  
  
- APIKit  
- APISandbox  
- APISandbox靶场通关  
- 安装  
- OWASPApiTop10  
- 4ASystem  
## APIKit  
  
APIKit是基于BurpSuite提供的JavaAPI开发的插件。  
  
APIKit可以主动/被动扫描发现应用泄露的API文档，并将API文档解析成BurpSuite中的数据包用于API安全测试。  
  
实际使用效果如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoHBUqwkxo3iclAeOe6Y1LAyiabsRszWHGy1wSrUpJksiaUib2NjAMicOfPdQ/640?wx_fmt=png&from=appmsg "")  
  
APIKit v1.0支持的API技术的指纹有：  
- GraphQL  
  
- OpenAPI-Swagger  
  
- SpringbootActuator  
  
- SOAP-WSDL  
  
- REST-WADL  
  
安装  
  
打开BurpSuite页面,点击Extender然后选择Extensions,添加APIKit.jar。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufo4iaibMqVkBx2Mg807T1PIM8bkbftDMUmDGoHBTd7tFVoQsgic83VnX8hw/640?wx_fmt=png&from=appmsg "")  
  
然后APIKit会对进入到BurpSuite的流量进行被动扫描。解析完成后可以在APIKit面板查看结果，同样Burpsuite的DashBoard也会有issue提示。  
## APISandbox  
- APISandbox是一个包含多个场景的API漏洞靶场。  
  
- 4ASystem: 4A认证系统下的API平行越权  
  
- APIVuln: 生产消费流水线中的API缓存投毒  
  
- GraphqlNotebook: 一个使用GraphQL的留言板以及经典API漏洞  
  
- InfoSystem: WSDL泄露API越权进后台Getshell  
  
- OASystem: SpringBoot微服务架构下的API Gateway配置问题  
  
- OWASPApiTop10: 使用go作为后端实现解释OWASP API Top 10的漏洞  
  
安装  
```
# 下载项目
wget https://github.com/API-Security/APISandbox/archive/refs/heads/main.zip -O APISandbox-main.zip
unzip APISandbox-main.zip
cd APISandbox-~~main

# 进入某一个漏洞/环境的目录
cd OWASPApiTop10

# 自动化编译环境
docker-compose build

# 启动整个环境
docker-compose up -d

```  
## APISandbox靶场通关  
### 安装  
  
下载靶场  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoDDfZk882shjAHOGoCQzzpiaUuMRvsgUtf4MKCE7drvOxHeicLznfvibKw/640?wx_fmt=png&from=appmsg "")  
  
自动化编译环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoxQHeDWr5vIxibqsZQSFq0IMIlYlJFRH27TZtGnbicWd7dVH3L65niaR0Q/640?wx_fmt=png&from=appmsg "")  
  
启动环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufouT5Ob50wNfb82liaFZVXKI5OkDAywfszgdqqTz4D0PjbHDz15OUCxJw/640?wx_fmt=png&from=appmsg "")  
  
看一下容器所在的端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoqsqmnhcscicZXU23ffrvPOibtiac9RKLZMr11ImzVQ9aeemBjWoK4yGwA/640?wx_fmt=png&from=appmsg "")  
  
访问对应的端口即可访问靶场  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoN4Miby8cn29hDyN5tdMrFqVLjjvEJWhEGTj15v93oH8NXWxXLnb3Fsw/640?wx_fmt=png&from=appmsg "")  
### OWASPApiTop10  
  
使用脚本进行扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoibDibXbdlEtLQMRe7gIDiavMnV5zQ5RS0wqMl27olUwVWic5MqbaibSmEiaw/640?wx_fmt=png&from=appmsg "")  
  
可以看到所有端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoVQ2Z42NX0zhu5lv9u6pMGjZL5nJdWyb9GWVLxCy0kDymZjU19Ro6Xw/640?wx_fmt=png&from=appmsg "")  
#### /v2/register接口任意用户注册  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoq5YFNXxAoaKEsQWibc7IWDYyoG3ibdPd0x9KAJfU6odppJpgyiaylgBsw/640?wx_fmt=png&from=appmsg "")  
  
其实这里也存在用户名枚举  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufotibdzsgRHWaZU5rvgF40pIrUfKicSSCgelTLk7JsMmUkUeqO5QVA8nuQ/640?wx_fmt=png&from=appmsg "")  
  
用户名存在的时候会提示  
```
{"code":1000,"msg":"Username has already been used!"}

```  
#### /v1/getenv接口未授权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoY5kcs1kET2ibtS4AsYpc3QI74PFibOJ4LpZtPceGKw39Lticpzx4EMGnA/640?wx_fmt=png&from=appmsg "")  
#### /v2/user/getuserinfo/2 水平越权  
  
首先需要使用/v2/login接口获取一个普通用户的cookie  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufotheY5gCcTBuzPT5Q196CAADMVJl9sib1Rem4M4XfOfg2vdoBFbE1d5w/640?wx_fmt=png&from=appmsg "")  
  
修改url中的数字即可越权获取其他用户的信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufogic0SpCzPkhQ2vykzOu0j9EJLIvfKZvamXzOh892UZNYzsXc7NroBDA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoQ21c0PAY04qhNaictibPwHtf0VP4uwecPU6ib4JywrIYpM5v62sduSiaicg/640?wx_fmt=png&from=appmsg "")  
#### /v2/user/getuserprofiles 垂直越权  
  
getuserprofiles接口垂直越权可获取所有用户的信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufov346X7Ql3YeqK4KJwsYK0q6PjaD5t4T5m6DYoWuccX2eM8ohyF6xlg/640?wx_fmt=png&from=appmsg "")  
#### /v2/login 暴力破解  
  
该接口没有验证码，可以进行暴力破解  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufo4ZHfiagcwYBYLWyibJs2mgt0lOqwZONNLplxrDB40iaL2V3MYUysNEgmw/640?wx_fmt=png&from=appmsg "")  
### 4ASystem  
  
安装  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoUlE9tYq77Xovjib3cpT6FTvzKUTSCc25pcGhVC3tOZibzB0mKUrtNrTQ/640?wx_fmt=png&from=appmsg "")  
  
安装完毕之后会有四个容器，我们先访问web1。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufolrpoUaEkgDCoOQe7yribgib7FzficUNiciakVC0BeUSNHlogFNRedIeEjZw/640?wx_fmt=jpeg&from=appmsg "")  
#### 弱口令登陆Web1应用  
  
登录接口存在弱口令admin/admin888  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufo3XRicwz3Aa2ibpNoibfI1W0aoZqogmrMhSXlia8cffjTSQ7Yowjru8j5NQ/640?wx_fmt=png&from=appmsg "")  
#### web1应用横向越权  
  
web1登录之后发现没啥东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufovicmXMzDM7kvqQzpW3KiclfhpAv3cLFDkvAAfZ8uibSrCbzdSKsjy3ibicg/640?wx_fmt=png&from=appmsg "")  
  
扫描目录发现www.zip存在源码s.php  
  
发现两个接口  
```
$loginapi = "http://192.168.10.10:8080/api/v1/sys_authenticate";
$resetapi = "http://192.168.10.10:8080/api/v1/sys_passwdreset";

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoVemtEM03x1BOibDHF79Ericvm5boic9CIUr4TH2mu88pF1TSmqRNxj3ug/640?wx_fmt=png&from=appmsg "")  
  
ChangePass函数用来修改web应用的密码。  
```
function ChangePass($url1, $url, $username, $oldpassword, $newpassword){
    $cookie = Login($url1, $username, $oldpassword);
    //$cookie = "MTYyNzU1NTA5NHxOd3dBTkRaS1VWaFNVMGhZVjFFMFdFZFFTMFZCVWpkTlVrVllOa2hYTlZBM05qVkpTa2MzTWpOT1ZETkNOakpKUWxoU1JrRkRVa0U9fLekjnGbigV2zA4BL9IPyp7Q6lzJ53hzvmB2TnIyBsXp";
    //echo $cookie;
    $data = array(
        'username'    => $username,
        'newpasswd'   => $newpassword,
        'application' => 'web1'
    );
    $curl = curl_init(); // 启动一个CURL会话
    curl_setopt($curl, CURLOPT_URL, $url); // 要访问的地址
    curl_setopt($curl, CURLOPT_POST, 1);             // 发送一个常规的Post请求
    curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));   // Post提交的数据包x
    curl_setopt($curl, CURLOPT_TIMEOUT, 30);         // 设置超时限制 防止死循环
    curl_setopt($curl, CURLOPT_HEADER, 1);           // 显示返回的Header区域内容
    curl_setopt($curl, CURLOPT_HTTPHEADER, array("Content-Type: application/json","Cookie: GOSESSID=$cookie;"));//设置请求头
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);   // 获取的信息以文件流的形式返回

    $res = curl_exec($curl); // 执行操作
    if(curl_errno($curl)) {
        header(500);//捕捉异常
    }
    $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
    curl_close($curl);

    $header = substr($res, 0, $header_size);
    $body = substr($res, $header_size);
    if(preg_match('/200/',$body)){
        return "success";
    }elseif (preg_match('/400/',$body)){
        return "reset Fail";
    }else{
        return null;
    }
}

```  
  
函数调用  
```
echo ChangePass($loginapi,$resetapi, $username, $oldpassword, $newpassword);

```  
```
$loginapi = "http://192.168.10.10:8080/api/v1/sys_authenticate";
$resetapi = "http://192.168.10.10:8080/api/v1/sys_passwdreset";

```  
  
也就是最终通过resetapi进行密码修改，构造一下请求数据包。  
  
首先使用loginapi获取api的凭证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVhaOiaZTXPbibDgAUS7kLufoRVcpBwEsnMwt36bkHv20pPYSxUeGAtIpLLHTIdkCnBl2NVNLew8T0g/640?wx_fmt=png&from=appmsg "")  
  
有了凭证访问resetapi即可越权修改web1、web2的应用密码。  
  
这里我不知道为啥访问接口404。  
  
  
