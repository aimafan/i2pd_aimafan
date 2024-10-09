# 工程版i2pd

## 主分支：openssl

包括日志系统和注释，不改变原来结点的内容

## 分支：link_explorer

针对I2P的链路或者连接信息，输出一份日志数据，包含链路的上一跳、下一跳等关键信息

## 分支：watermark_middle
流水印攻击中的中继节点

最终可能输出一个日志，将我收到和发出去的数据包都放到日志里面，包括这个数据包是TCP或者UDP的，然后属于哪个隧道，发给哪个IP或者从哪个IP接收的。日志结构：

发/收 ; TCP/UDP ; 隧道身份（participant、endpoint、gateway） ; IP ; 端口 ; ident ; 包类型 ; 包长度 