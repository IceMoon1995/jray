# jray

一款弱小的被动扫描安全评估工具，目前不支持主动扫描哦！！！

由于开始编写时，对go语言不熟悉，导致挖了很多坑，慢慢填吧

缝合怪导致框架架构不是很好，但是重复造轮子的话导致工作量大幅度提升，还是随便写写吧

参考w13scan被动扫描器[https://github.com/w-digital-scanner/w13scan] ，本来是改了好多w13scan的代码，但是过程中发现python不是很好，效率比较低，某些情况下丢包非常严重。

代理模块使用go-mitmproxy[https://github.com/lqqyt2423/go-mitmproxy] ，去除了项目有一部分remote error等影响软件正常使用的报错的提示。

poc扫描插件主要使用fscan[https://github.com/shadow1ng/fscan] 修改版本，xray的yml脚本，以及自己编写的部分插件。


目前支持自定义插件，主要增强子目录，泄露文件扫描功能。

原因 xray是非常优秀的安全评估工具，但是目前是闭源的无法修改源代码。在某些小众场景下（如：自研的项目黑盒测试），xray子目录扫描不够全面，可扩展性不足。


## 使用方式

fray.exe 默认监听9080端口，9081端口（web界面）

## 参数说明
```
-t int
      指定并发线程默认16，根据丢包情况自行修改（yml扫描自带20个线程，目前未处理）
-addr str
      指定http代理监听端口
-waddr str
      指定web界面监听端口
-dump filenmae
      指定mitm获取的报文存储路径
-dump_level int
      0:表示只存请求头，1:保存请求头和请求体
-nosave
      是否输出漏洞结果到文件
-cert_path str
      指定MITM仿造的证书存储位置
-o filename
      指定漏洞输出地址


```


## 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。
除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。


## TODO
[+] 新增sql注入插件

[+] 增加xss插件

[+] 增加二级代理功能

[+] 增加白名单设置
