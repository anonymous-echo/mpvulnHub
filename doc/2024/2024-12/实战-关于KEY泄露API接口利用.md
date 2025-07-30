#  实战-关于KEY泄露API接口利用   
和  神农Sec   2024-12-19 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
  
原文链接：https://zone.huoxian.cn/d/2909-keyapi  
  
作者：和  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
最近做项目遇见的各个平台的Key泄露的比较多，正好总结一下关于API接口利用的内容分享一下。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 微信公众号泄露AppID+AppSecert利用**  
  
####    
  
前期通过打点获取到的数据库，互联网连接mysql发现了多个公众号AppID和AppSecert。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzBaEOQMHdlSib9MHn3KvDEcDic9ic34tEDXY8zKLPyMYQxibIz6HVhdpRKA/640?wx_fmt=png&from=appmsg "")  
  
  
这里查询微信公众号的接口权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzb11PEHXyaWKAprfNbfyXSkNsdBjKd2nozURwQoxuWvfpXCAndfC5Kg/640?wx_fmt=png&from=appmsg "")  
  
默认的接口权限未认证用户都是很基础的。利用微信公众号接口调试工具  
  
  
测试下载文件接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddz2TN56kkstTrVoiaxwnRfwX9ORf501WWkOm6QdvZgibnTvVkM3qyq4fDw/640?wx_fmt=png&from=appmsg "")  
  
  
测试上传文件接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzHcd4AMZq2TjoxggBYI5whet86wngj7BoJW8NmfTGBZtUHr30qkC6Lg/640?wx_fmt=png&from=appmsg "")  
#####   
##### AccessToken泄露  
  
在某些路径泄露的时候可能会直接获取到外带的AccessToken，虽然AccessToken的时效性最长不超过两个小时，一般失效型都在一个多小时，利用泄露的AccessToken可直接调用  
#####   
##### 利用难度  
- 目前关于AccessToken的获取时效性两小时，利用AppID和AppSecert获取AccessToken有白名单限制，但是在实际利用获取AccessToken的时候除了测试环境，目前真实环境我还没遇到过关于非白名单获取失败的报错，测试的时候发现反而限制的比较死。  
  
- 再利用微信公众平台泄露的key时，已认证的微信公众平台可调用的接口是比较多的，例如：用户管理等。未认证的账号一般仅有基础接口可调用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 程序Appid+AppSecert泄露**  
  
  
小程序接口**Web.rar**  
泄露的文件中发现了三个小程序的Appid+AppSecert  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddziaQPPQwqAbq8WxYZm9qNcpSM3U5NnbgaEVjI31eTfkyjiaqGlDUgpSrA/640?wx_fmt=png&from=appmsg "")  
  
  
利用API接口获取设备型号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddznR20T4qCHw8gXE7KTWDaGA3Miao2ZWktrvUMHsfaJKX9TNah8l75AFA/640?wx_fmt=png&from=appmsg "")  
  
  
调用接口获取用户id  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzFqJGvCTyfGBiczWALlPAv8QIJ2ZlFykoOJWBpriaibZNG8nGQMgbbnFvQ/640?wx_fmt=png&from=appmsg "")  
####   
####   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 德地图ApiKey利用**  
  
  
JS文件信息泄露了高德的ApiKey  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddz2Y01lfkgTiblA23KQ97cAY3IxXE35EGQPJDTXLyy0pOr8JDodLImWAw/640?wx_fmt=png&from=appmsg "")  
  
  
python脚本实现调用APIKey查询周边兴趣点  
```
# -*- coding: utf-8 -*-
import requests
import json
def search_poi(api_key, keyword, city="全国"):
    url = f"https://restapi.amap.com/v3/place/text?key={api_key}&keywords={keyword}&city={city}"
    response = requests.get(url)
    result = response.json()
    if result['status'] == '1':
        pois = result['pois']
        for poi in pois:
            name = poi['name']
            location = poi['location']
            print(f"Name: {name}, Location: {location}")
    else:
        print("POI Search failed:", result['info'])
def search_place(api_key, keywords, city='北京'):
    base_url = 'https://restapi.amap.com/v3/place/text'
    params = {
        'key': api_key,
        'keywords': keywords,
        'city': city,
        'output': 'json'
    }
    response = requests.get(base_url, params=params)
    data = response.json()
    return data
def search_route(api_key, origin, destination, city='北京', mode='driving'):
    base_url = 'https://restapi.amap.com/v3/direction/' + mode
    params = {
        'key': api_key,
        'origin': origin,
        'destination': destination,
        'city': city,
        'output': 'json'
    }
    response = requests.get(base_url, params=params)
    data = response.json()
    return data
def search_geocode(api_key, address, city='北京'):
    base_url = 'https://restapi.amap.com/v3/geocode/geo'
    params = {
        'key': api_key,
        'address': address,
        'city': city,
        'output': 'json'
    }
    response = requests.get(base_url, params=params)
    data = response.json()
    return data
if __name__ == "__main__":
    api_key = input("请输入你的高德Web服务API Key: ")
    address1 = input("请输入你的起始地址: ")
    address2 = input("请输入你的目的地址: ")
    data1 = search_geocode(api_key, address1)
    geocodes1 = data1.get('geocodes', [])
    location1 = 'N/A'
    for geocode in geocodes1:
        location1 = geocode.get('location', 'N/A')
        print(f"起始地址: {address1}, 经纬度: {location1}")
    data2 = search_geocode(api_key, address2)
    geocodes2 = data2.get('geocodes', [])
    location2 = 'N/A'
    for geocode in geocodes2:
        location2 = geocode.get('location', 'N/A')
        print(f"目的地址: {address2}, 经纬度: {location2}")
    data = search_route(api_key, location1, location2)
    route = data.get('route', {})
    path = route.get('paths', [{}])[0]
    distance = path.get('distance', 'N/A')
    duration = path.get('duration', 'N/A')
    print(f"距离: {distance}, 预计时长: {duration}")
    # 示例：POI搜索
    keyword = input("请输入关键词进行POI搜索：")
    search_poi(api_key, keyword)
```  
  
  
路径规划、POI搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzyBB5AmgUPSYic51G2AQ1J0Las37xyXlLTLpQCqKV9MBzIaTEJIYdaibw/640?wx_fmt=png&from=appmsg "")  
  
  
查询经纬度  
```
import requests
def get_geocode(api_key, address, city='北京'):
    base_url = 'https://restapi.amap.com/v3/geocode/geo'
    params = {
        'key': api_key,
        'address': address,
        'city': city,
        'output': 'json'
    }
    response = requests.get(base_url, params=params)
    data = response.json()
    return data
if __name__ == "__main__":
    api_key = input("请输入你的高德Web服务API Key: ")
    while True:
        address = input("请输入你想要查询经纬度的地址（输入exit退出）: ")
        if address.lower() == "exit":
            break
        data = get_geocode(api_key, address)
        geocodes = data.get('geocodes', [])
        if geocodes:
            for geocode in geocodes:
                location = geocode.get('location', 'N/A')
                print(f"地址: {address}, 经纬度: {location}")
        else:
            print("未找到该地址，请重新输入。")
```  
  
  
地址编码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzicmJLp5Blg681PCUPeBbHhACGJX8kuwykA833JDZdiaqWsP7Kz84vfXA/640?wx_fmt=png&from=appmsg "")  
  
  
关于高德ApiKey的泄露风险，普通用户的高德额度调用量是有限制的，当key泄露之后，可以高频次调用，导致产生大量的额外费用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzB3qiaEHgBdUz7Rq8m7IWZic4qG4uYRhwEbxXd22za9CUox4DiaRztxicpA/640?wx_fmt=png&from=appmsg "")  
  
  
可以根据高德的付费要求，单接口的流量包都是费用如下，提供的接口越多，费用随之升高，泄露的风险就是可能造成资源浪费。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzOEuCiaxt0zt5VSVUvNYLvJCAg0hSGCf05D9ZUq0DTuMrQ07d49q9AHg/640?wx_fmt=png&from=appmsg "")  
#####   
##### 利用难度  
- 无白名单机制限制，利用难度低  
  
- 危害程度除资源消耗无其它影响。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 百度地图Apikey利用**  
  
   
  
这里直接测试的地址检索  
```
# -*- coding: utf-8 -*-
import requests
def place_search(query, region, api_key):
    url = f"http://api.map.baidu.com/place/v2/search?query={query}&region={region}&output=json&ak={api_key}"
    response = requests.get(url)
    try:
        response.raise_for_status()  # 检查请求是否成功
        data = response.json()
        if data["status"] == 0:
            results = data["results"]
            for idx, result in enumerate(results, start=1):
                print(f"{idx}. {result['name']}: {result['address']}")
        else:
            print("地点检索失败:", data["message"])
    except requests.exceptions.RequestException as e:
        print("请求错误:", e)
def main():
    query = input("请输入要搜索的地点关键词：")
    region = input("请输入搜索的区域（如城市名称）：")
    api_key = input("请输入百度地图开放平台的 API Key：")
    place_search(query, region, api_key)
if __name__ == "__main__":
    main()
```  
  
  
检索关键字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzIF1qXf06CcWoYicmAibhocEw220CMOjkc4WPAXnlvD6YLGhDhmkqk4VQ/640?wx_fmt=png&from=appmsg "")  
####   
####   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x6 OSS存储桶AK/SK泄露**  
####    
  
接上一次的红队，信息搜集的时候发现这家关联单位的存储桶泄露的AK/SK。  
  
入口：web系统弱口令，发现配置文件脱敏  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzEHn7RM40DKiacYMAzMDUsTvmmJYKjEDFxolCvVzHkD7ibkekWuGSib0IQ/640?wx_fmt=png&from=appmsg "")  
  
  
继续搜集应用功能发现泄露了Git的账号密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzIhibnlXxE3qImJJtGwvvq6rNvy4FONiahaYjOgMyGjJB6qyqhjfHWPxw/640?wx_fmt=png&from=appmsg "")  
  
  
git登录拉取文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzjNMTahiaT5IrO8gIWMlabz89xhgyM8ZRicycn5Diapbtaibn57nBfnhU3w/640?wx_fmt=png&from=appmsg "")  
  
  
找到AK和SK  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzvlIsAAyEyVvc3PIXTM5mXGReIsxdKZ2s4juZkNUxEJkIw85hSLk1UA/640?wx_fmt=png&from=appmsg "")  
  
  
除了带锁的无法访问，存储桶内数据共计800G+  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVeCum5SMmq8CXM0LNqzddzhVjCOfwNQm9ISt6N6Eib7acZvjB1buEQlnPQr6SBxGemzoG4FBodRIg/640?wx_fmt=png&from=appmsg "")  
####   
####   
####   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x7 总结**  
  
  
  
公众号的测试+小程序的api调用认证用户的高级接口和存储桶的利用危害是最直观的，地图的API泄露一般只会产生经济效益。  
  
  
我们是神农安全，  
**点赞 + 在看**  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、微信小群一起挖洞
5、不定期有众测、渗透测试项目
```  
  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWBeNFS2WNPd2FJ1SmqGkcf3s0DkMZicbriaUEuXagWt2eqxBWkUXRyQabIczmNAT5nTxc9tvaBzlww/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满200人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
  
