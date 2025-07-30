> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNzM2MjM0OQ==&mid=2247498053&idx=1&sn=39c80a5dae7fa17d81aa9149cf37d9a1

#  某商城-js注入拦截JSON.parse方法  
原创 差不多张三  隐雾安全   2025-07-15 01:02  
  
**No.1**  
  
**正文**  
  
  
****  
点击分类  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FianbLn8EE6avoLz5VlhfRAiaJ2zAkYDCiaRP9dF7sS9wDicT0r6LLmc7iaTQ/640?wx_fmt=png&from=appmsg "")  
  
  
请求响应加密  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaTVk2RIVfvPCdRSnttvU7w5XvUfyMACPx2c2TUtRBFQxYR90Zo1Byeg/640?wx_fmt=png&from=appmsg "")  
  
  
控制台注入js调试代码，hook JSON.parse方法  
  
(function() {  
  
    var parse = JSON.parse;  
  
    JSON.parse = function(params) {  
  
        console.log("Hook JSON.parse ——> ", params);  
  
        debugger;  
  
        return parse(params);  
  
    }  
  
})();  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaSaiaiaJQp9ibrwicavhQgTqVwSFr8QE2og05kUOKRqJFqt962je00Anbicw/640?wx_fmt=png&from=appmsg "")  
  
  
再次点击分类，自动断点在了JSON.parse方法调用处  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaALnANshQTcSsNeicp6hHOk3KL5hv0no5KgVZoIMrvMOJOQ5oXicZia6lQ/640?wx_fmt=png&from=appmsg "")  
  
  
点击多次继续执行脚本  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiamN4icqHtb4sL0LpwDOl1VYQoyk0p3A9xpmCRribucKYaukTYUxwv1KvQ/640?wx_fmt=png&from=appmsg "")  
  
  
直到出现明文数据，对比页面显示结果发现是响应内容的明文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaFFMmU5pjnYefj9QXHZl1oTRUhDWkFUapW9IfLibiaTbo1EW3NfXqPfYw/640?wx_fmt=png&from=appmsg "")  
  
  
跟踪调用堆栈，在返回值处下断点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7Fiab97kR50OZlyk0p1aWtwiaTMOg8BNc7A4nBb0jC4t1jellROQYib8p2Uw/640?wx_fmt=png&from=appmsg "")  
  
  
发现t.data是密文，g是密钥，l.a是解密函数  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaDmwqbswaibvDiccYmETjvtjQb02hDGdu8uicYTRh3niazTD7eXicziawlkXg/640?wx_fmt=png&from=appmsg "")  
  
  
进到l.a函数内部，在u.a.AES.decrypt(t, n, d).toString(u.a.enc.Utf8)下断点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7Fia5FSCovM5oCUCa4MtJLVLiaDAu1LicYiap8DIQETPAVkG4WR9GO3UIa4zQ/640?wx_fmt=png&from=appmsg "")  
  
t是响应密文，n是密钥，d是iv，将第二步响应赋值给t，调用  
  
u.a.AES.decrypt(t, n, d).toString(u.a.enc.Utf8)解密成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7Fiax6LWgzic5fcW4hYW3QL9SRbtHF5ibS2o7YCkgRameCamYTUOdhgkfNhg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaayZLVsibhZvX3fiaOnoWotpmhWheAEFDejp4RebeU5jxHoBmoMTibrdEQ/640?wx_fmt=png&from=appmsg "")  
  
  
请求内容分为两个部分，前面是COOKIE，后面是请求密文，以管道符间隔  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7Fiat4peHxJ5icqOWx2rJs2zFqUKXKcHibibuBWlrPtdjXApUThTJEvtBE2xA/640?wx_fmt=png&from=appmsg "")  
  
  
将请求密文赋值给t，解密成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiauJA1wBNNibc3ZFVuz4HORsJ2Jqf3vNwmTCxvMvwe9ia0KwSe1jO2PZzw/640?wx_fmt=png&from=appmsg "")  
  
  
发现u.a.AES对象还有一个加密方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiapqXhMJsPqYibh7eiaIaQiaBjFxO9HsVsyySJuLOo2XTslreP0IzR4gKEg/640?wx_fmt=png&from=appmsg "")  
  
  
定位到u.a.AES.encrypt(t, n, d).toString()，将第十二步请求明文赋值给t，对比数据包加密成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yl56P8icYDszLPJLKiaGN7Fiayb6zSDFYpeAcHBibkY2OtJtGmYaIKUo7CFbbq7H1ZhUEOsE8Ukrc9ag/640?wx_fmt=png&from=appmsg "")  
  
  
**No.2**  
  
**网安沟通交流群**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34yl56P8icYDszLPJLKiaGN7FiaRH0w1wYGgF30s7VeWjQWLyM7eTXibNxQ5ucialNMo8FukEB6SpsUDMQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**扫码加客服小姐姐拉群**  
  
  
  
