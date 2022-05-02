# jray

一款弱小的被动扫描安全评估工具，目前不支持主动扫描哦！！！

由于开始编写时，对go语言不熟悉，导致挖了很多坑，慢慢填吧

代理模块使用go-mitmproxy[https://github.com/lqqyt2423/go-mitmproxy] ,去除了项目部分remote error等影响工程正常使用的报错的提示

poc扫描插件主要使用gopoc[https://github.com/jjf012/gopoc] 修改版本，xray的yml脚本，以及自己编写的部分插件
