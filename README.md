# DPDK_libnids
First try on DPDK with libnids
最近领导提出需要开发一款基于DPDK的快速网络包还原软件，所以就采用了libnids的网络包分片重组功能，在libnids1.24源码基础上，对数据源进行了修改，换用DPDK，就当是学习DPDK的一次练习。
本项目只是一次实验项目，其中有些代码可能比较冗余，目前已经在Linux EHL 7.2/Ubuntu 15上进行了抓包及HTTP协议还原测试，已经能够准确还原出传输的文件。