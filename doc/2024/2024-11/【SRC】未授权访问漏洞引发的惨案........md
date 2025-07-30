#  【SRC】未授权访问漏洞引发的惨案.......   
 朱厌安全   2024-11-14 17:50  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.3290816606122484&random=0.9517387405783253&random=0.43431524734947935&random=0.237828936192382&random=0.9537626908424166&random=0.6387630464803715&random=0.919847720603056 "")  
  
喜欢就关注我吧！  

				  
  
   
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！  
## 1前言  
  
本文记录了最近的一次src漏洞挖掘，并成功获取到严重漏洞的过程，通过组合拳的方法从未授权访问到获取管理员后台。  
## 2准备工作  
  
该网站具有学生和教师两个角色权限，首先注册学生用户后发现权限较低，尝试注册教师用户，教师权限比学生权限要高。  
  
   
  
**1**  
  
**第一步获取token**  

				  
##  进入后获取token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbOugVFrHEY9Ea29uXru05bpAvUPek1oSnpkzVEaX4TO22FpmklBAhn2Q/640?wx_fmt=png&from=appmsg&random=0.12474528322471956&random=0.22236825794021065&random=0.19238124719161798&random=0.7706401021068534&random=0.6331112738812275&random=0.07593278256944358&random=0.041370982055274785&random=0.6842279317928417 "")  
  
教师token  
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjE5NTQ1NjczODQwIiwiZXhwIjoxNzI0OTAwNDMzfQ.gOCnzTizCYxF0MKDt3NshtKPyWvd67AOUp9Wr0C7V34

```  
  
   
  
**2**  
  
**第二步token伪造**  

				  
##  通过jwt伪造admin用户的token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbOEr2j3vKasbILmtocMfko3ObdGCFbIVeZayLahNZ2pFzjlMFqw7fGRw/640?wx_fmt=png&from=appmsg&random=0.5126000284724266&random=0.9173590569038141&random=0.3418087461512138&random=0.7672650134423697&random=0.9650332229174015&random=0.7930317131646085&random=0.4649993023355512&random=0.7780990020327263 "")  
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI0ODk3MTgzfQ.nL7duNpjz0lId9kkYtViQCV_LnGAP9VXd6RGfsk0vtU
```  
  
因为该站点泄漏了接口文档，所以可以通过接口获取所有管理员的账号信息，但是此时是没有密码的  
  
接口来源：https://xxxxx/xxx/api/xxxx/xxx 构造数据包   
  
（1）使用上述注册的普通教师用户的token调用接口，查看到的信息较少，权限较低  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbOQoUvBh1uLkGEHYVj8Re0dpdkic8G2ljAsC5ic7ibyVMF8xOdQcG1BjLOw/640?wx_fmt=png&from=appmsg&random=0.8753611430318766&random=0.263125606538674&random=0.4014590980825108&random=0.7565277519317741&random=0.5819198796078202&random=0.18975209114352642&random=0.9338199582772806&random=0.07498989628075647 "")  
  
（2）使用伪造admin用户后的token进行验证，能看到的信息较多  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbOtdL9fooGm8ck5O7wzVtIGM0PgE4LKfKew7ZzIfE0dQausI5hdqIJjg/640?wx_fmt=png&from=appmsg&random=0.06544249687894999&random=0.36988901682598696&random=0.6620606892867515&random=0.9610748234122923&random=0.4539575687421733&random=0.09871159625415893&random=0.6008393773012317&random=0.0022504509072731604 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbOz4AlN06uAGyqZXLI86PoPFp6C4rr4q1YDjStyH8vFT8v8CCRjsEXGg/640?wx_fmt=png&from=appmsg&random=0.3658774706948489&random=0.186272286931372&random=0.0638241618515385&random=0.1727105507560205&random=0.16300842606273314&random=0.724012203773724&random=0.9959427752336258&random=0.16415837111654485 "")  
  
即可获取一千多个用户的个人信息
修改参数为current为2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbOuf8djic0Efdk9QzlicVx9iaIC6RvFEf9rYQJt3R39BxEGSqoxLCRjXicyg/640?wx_fmt=png&from=appmsg&random=0.5530850593862524&random=0.21391013630711697&random=0.9528038849832721&random=0.8881202011353415&random=0.04382447465515216&random=0.7423721691916325&random=0.5160754785087069&random=0.7247604816744111 "")  
  
由上获取所有管理员账号，尝试用123456进行密码喷洒，成功使用弱口令登录到到超级管理员用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbO7NDka3kcLQSRgSYPE6jWOibNkADOU0wJR0QYdsMcj3ZrR2IL9awHZyQ/640?wx_fmt=png&from=appmsg&random=0.024465541587981088&random=0.8484810294382599&random=0.15354010693071451&random=0.349290321592739&random=0.11404481515799603&random=0.3870339860448859&random=0.7286861838666567&random=0.12539335507268734 "")  
  
登录后所有功能均有权限，其中泄漏包括业务数据，一千多条用户信息，以及订单信息等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hcaMvQ2BB2zMuFMSHXkV7Ca3ajedakbORIZ6vEsn9MfUxYusSzzvldKnWVsumNmJnvfBwuLXN7H2waOMsJSDeA/640?wx_fmt=png&from=appmsg&random=0.10980474385817107&random=0.07671556204031149&random=0.8240894567117358&random=0.7488330200895952&random=0.20561622536410828&random=0.6380179663020875&random=0.2895443232555346 "")  
  
  
**END**  
  
  
