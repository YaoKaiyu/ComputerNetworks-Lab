# 实验11 · 网络路由实验一

#### 吴嘉皓

## 一、实验内容

修改`mospf_daemon.c`文件，实现路由器**生成**和**处理**mOSPF **Hello/LSU**消息的相关操作，构建**一致性链路状态数据库**；即，完成**以下函数**：

1. 生成mOSPF Hello消息（***sending_mospf_hello_thread***）；
2. 生成mOSPF LSU消息  （***sending_mospf_lsu_thread***）；
3. 处理mOSPF Hello消息（***handle_mospf_hello***）；
4. 处理mOSPF LSU消息  （***handle_mospf_lsu***）；
5. 检查老化邻居操作       （***checking_nbr_thread***）；



## 二、实验流程

### （一）代码目录

```bash
2015K8009915007_吴嘉皓_11.tar.gz
		├── 11-mospf  # 代码工程目录
		└──实验11-网络路由实验一·实验报告.pdf
```

### （二）测试流程

在 `11-mospf`目录下输入如下命令：

```bash
make
sudo python topo.py
mininet> # 等待10s左右(我已经将topo.py中的注释部分取消，四个节点的结果会重定向至四个txt中)
mininet> exit
# 查看 r*-output.txt
# 比对数据库的结果
```



## 三、实验结果

* 图一：实验数据库结果输出

![image-1](https://github.com/framywhale/ComputerNetworks-Lab/blob/master/src/11/1.png)

* 图一中的输出结果格式为:
> **rid** 

> neighbours (**SUBNET, MASK, neighbour's RID**)

* 图二：此次实验网络拓扑图
![image-2](https://github.com/framywhale/ComputerNetworks-Lab/blob/master/src/11/2.png)

## 四、结果分析

### （一）实验结果分析

由上图可见：各节点的数据库分别如下：

* **r1** 的数据库

    |   RID    |  SUBNET  |     MASK      | NEIGHBOUR |
    | :------: | :------: | :-----------: | :-------: |
    | 10.0.2.2 | 10.0.3.0 | 255.255.255.0 | 10.0.1.1  |
    | 10.0.2.2 | 10.0.5.0 | 255.255.255.0 | 10.0.4.4  |
    | 10.0.3.3 | 10.0.3.0 | 255.255.255.0 | 10.0.1.1  |
    | 10.0.3.3 | 10.0.5.0 | 255.255.255.0 | 10.0.4.4  |
    | 10.0.4.4 | 10.0.4.0 | 255.255.255.0 | 10.0.2.2  |
    | 10.0.4.4 | 10.0.5.0 | 255.255.255.0 | 10.0.3.3  |

* **r2** 的数据库

    |   RID    |  SUBNET  |     MASK      | NEIGHBOUR |
    | :------: | :------: | :-----------: | :-------: |
    | 10.0.1.1 | 10.0.2.0 | 255.255.255.0 | 10.0.2.2  |
    | 10.0.1.1 | 10.0.3.0 | 255.255.255.0 | 10.0.3.3  |
    | 10.0.3.3 | 10.0.3.0 | 255.255.255.0 | 10.0.1.1  |
    | 10.0.3.3 | 10.0.5.0 | 255.255.255.0 | 10.0.4.4  |
    | 10.0.4.4 | 10.0.4.0 | 255.255.255.0 | 10.0.2.2  |
    | 10.0.4.4 | 10.0.5.0 | 255.255.255.0 | 10.0.3.3  |

* **r3** 的数据库

    |   RID    |  SUBNET  |     MASK      | NEIGHBOUR |
    | :------: | :------: | :-----------: | :-------: |
    | 10.0.1.1 | 10.0.2.0 | 255.255.255.0 | 10.0.2.2  |
    | 10.0.1.1 | 10.0.3.0 | 255.255.255.0 | 10.0.3.3  |
	| 10.0.2.2 | 10.0.3.0 | 255.255.255.0 | 10.0.1.1  |
    | 10.0.2.2 | 10.0.5.0 | 255.255.255.0 | 10.0.4.4  |
    | 10.0.4.4 | 10.0.4.0 | 255.255.255.0 | 10.0.2.2  |
    | 10.0.4.4 | 10.0.5.0 | 255.255.255.0 | 10.0.3.3  |

* **r4** 的数据库

    |   RID    |  SUBNET  |     MASK      | NEIGHBOUR |
    | :------: | :------: | :-----------: | :-------: |
    | 10.0.1.1 | 10.0.2.0 | 255.255.255.0 | 10.0.2.2  |
    | 10.0.1.1 | 10.0.3.0 | 255.255.255.0 | 10.0.3.3  |
    | 10.0.2.2 | 10.0.3.0 | 255.255.255.0 | 10.0.1.1  |
    | 10.0.2.2 | 10.0.5.0 | 255.255.255.0 | 10.0.4.4  |
    | 10.0.3.3 | 10.0.3.0 | 255.255.255.0 | 10.0.1.1  |
    | 10.0.3.3 | 10.0.5.0 | 255.255.255.0 | 10.0.4.4  |

由上述可见，**成功**构建了**一致性**数据库。

### （二）代码实现分析

* `void *sending_mospf_hello_thread(void *param)`
    * 该函数每隔1s发送一次mospf hello消息
    * 每次构造一个mospf hello类型的包
        * 初始化 ether header (`src: iface->mac`,  `dst: 固定多播地址（01:00:5E:00:00:05） `)
        * 初始化 ip header (`src: iface->ip`, `dst: 固定多播地址224.0.0.5`)
        * 初始化 mospf header (`rid = instance->rid`)
        * 计算mospf和ip的检验和
        * 通过`iface_send_packet`发送该包

   代码如下：

```c
void *sending_mospf_hello_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
    char * packet = NULL;
    iface_info_t * iface = NULL, * iface_q = NULL;
    struct ether_header * eth   = NULL;
    struct iphdr        * ip    = NULL;
    struct mospf_hdr    * mospf = NULL;
    struct mospf_hello  * hello = NULL;
    // 01 : 00 : 5E : 00 : 00 : 05
    static u8 MOSPF_ALLSPFMac[ETH_ALEN] = {0x1, 0x0, 0x5e, 0x0, 0x0, 0x5};
    while (1) {
        // printf("sending_mospf_hello_thread.\n");
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            packet = (char *)malloc(HELLO_PACKET_LEN);
            if (!packet) {
                printf("send hello thread malloc packet error.\n"); exit(-1);
            }
            // init ether header
            eth = (struct ether_header *)packet;
            memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
            memcpy(eth->ether_dhost, MOSPF_ALLSPFMac, ETH_ALEN);
            eth->ether_type = ntohs(ETH_P_IP);
            // init ip header
            ip = packet_to_ip_hdr(packet);
            ip_init_hdr(ip,                                   // iphdr
                        iface->ip,                            // saddr
                        MOSPF_ALLSPFRouters,                  // daddr
                        HELLO_PACKET_LEN - ETHER_HDR_SIZE,    // tot_len
                        IPPROTO_MOSPF);                       // protocol
            // init mospf header
            mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
            mospf_init_hdr(mospf,                             // mospf_hdr
                           MOSPF_TYPE_HELLO,                  // mospf type
                           MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, // mospf len
                           instance->router_id,               // rid
                           0);                                // aid
            // init mospf hello
            hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
            mospf_init_hello(hello, iface->mask);
            // update checksum of ip header and mospf header
            mospf->checksum = mospf_checksum(mospf);
            ip->checksum = ip_checksum(ip);
            // send packet through iface_send_packet()
            iface_send_packet(iface, packet, HELLO_PACKET_LEN);
        }
        sleep(MOSPF_DEFAULT_HELLOINT);
    }
    return NULL;
}
```

* `void *checking_nbr_thread(void *param)`
    * 该函数每隔1s检查一下邻居列表，如果有超时的项，删去，并发送lsu消息
    * 每次检查时候会对每一项邻居的alive++（即，距离上一次更新过了x秒）
    * 在`handle_mospf_hello`中，如果收到的消息中的节点已经存在在邻居列表中，会将该邻居的alive置零，即更新到达时间。

代码如下：

```c
void *checking_nbr_thread(void *param) {
    // fprintf(stdout, "TODO: neighbor list timeout operation.\n");
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    while (1) {
        // printf("checking_nbr_thread.\n");
        pthread_mutex_lock(&mospf_lock);
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    if ((nbr_entry->alive++) > MOSPF_NEIGHBOR_TIMEOUT) {
                        list_delete_entry(&(nbr_entry->list));
                        iface->num_nbr--;
                        printf("DEBUG: Delete timeout neighbor.\n");
                        send_mospf_lsu();
                    }
                }
            }
        }
        pthread_mutex_unlock(&mospf_lock);
        sleep(1);
    }
    return NULL;
}
```

* `void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)`
    * 该函数用来处理收到的hello消息
        * 如果在邻居列表中发送该消息的节点已经存在，更新其到达时间（alive置零）；
        * 否则，在邻居列表中插入新的表项，并发送lsu消息；

代码如下：

```C
void handle_mospf_hello(iface_info_t *iface, const char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    struct mospf_hdr   * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_hello * hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
    mospf_nbr_t * nbr = NULL, * nbr_q = NULL;
    int found = 0;
    pthread_mutex_lock(&mospf_lock);
    if (!list_empty(&(iface->nbr_list))) {
        list_for_each_entry_safe(nbr, nbr_q, &(iface->nbr_list), list) {
            if (nbr->nbr_id == ntohl(mospf->rid)) {
                nbr->alive = 0;
                found = 1;
                break;
            }
        }
    }
    // nbr is empty or neighbour not found
    // add new router to list
    if (!found) {
        (iface->num_nbr)++;
        mospf_nbr_t * new_nbr = (mospf_nbr_t *)malloc(MOSPF_NBR_SIZE);
        new_nbr->nbr_id   = ntohl(mospf->rid);
        new_nbr->nbr_ip   = ntohl(ip->saddr);
        new_nbr->nbr_mask = ntohl(hello->mask);
        new_nbr->alive    = 0;
        list_add_tail(&(new_nbr->list), &(iface->nbr_list));
        send_mospf_lsu();
    }
    pthread_mutex_unlock(&mospf_lock);
}
```

* `send_mospf_lsu()`
    * 该函数用来发送lsu消息：
        * 先遍历本节点的所有邻居，计算出需要多少个lsa；
        * 然后，再构造`lsa_packet`以便之后生成包的时候直接拷贝；
        * 接着就是生成包来给本节点所有的邻居节点发送lsu消息；
            * 其中，每发送一个lsu消息， `instance->seqence_num`就需要加1；

代码如下：

```c
void send_mospf_lsu() {
    // pre-declarations of variables
    struct iphdr        * ip    = NULL;
    struct mospf_hdr    * mospf = NULL;
    struct mospf_lsu    * lsu   = NULL;
    struct mospf_lsa    * lsa   = NULL;
    char * packet = NULL, * lsa_packets = NULL;
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    // count the number of neighbours
    int nbr_num = 0;
    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list)
            nbr_num += iface->num_nbr;
    }
    // get informations of all neighbours into lsa
    lsa_packets = (char *)malloc(nbr_num * MOSPF_LSA_SIZE);
    if (!lsa_packets) {printf("lsa_packets malloc error.\n"); exit(-1);}
    if (!list_empty(&(instance->iface_list))) {
        struct mospf_lsa * lsa_idx = (struct mospf_lsa *)lsa_packets;
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    lsa_idx->subnet = htonl(nbr_entry->nbr_ip & nbr_entry->nbr_mask);
                    lsa_idx->mask   = htonl(nbr_entry->nbr_mask);
                    lsa_idx->rid    = htonl(nbr_entry->nbr_id);
                    lsa_idx++;
                }
            }
        }
    }
    // generate LSU packet and send it through ip_send_packet();
    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    // update seq_num
                    instance->sequence_num++;
                    // set up new lsu packet
                    packet = (char *)malloc(LSU_PACKET_LEN(nbr_num));
                    if (!packet){
                        printf("send_mospf_lsu: packet malloc error.\n"); exit(-1);
                    }
                    // ATTENTION: ether header will be set in ip_send_packet()
                    // init ip header
                    ip = packet_to_ip_hdr(packet);
                    ip_init_hdr(ip,                                       // ip_hdr
                                iface->ip,                                // saddr
                                nbr_entry->nbr_ip,                        // daddr
                                LSU_PACKET_LEN(nbr_num) - ETHER_HDR_SIZE, // tot_len
                                IPPROTO_MOSPF);                           // protocol
                    // init mospf header
                    mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
                    int mospf_len = LSU_PACKET_LEN(nbr_num)
                                  - ETHER_HDR_SIZE - IP_HDR_SIZE(ip);
                    mospf_init_hdr(mospf,                // mospf_hdr
                                   MOSPF_TYPE_LSU,       // mospf type
                                   mospf_len,            // len
                                   instance->router_id,  // rid
                                   0);                   // aid
                    // init mospf lsu part
                    lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
                    mospf_init_lsu(lsu, nbr_num);  // lsu, lsu->nadv
                    // set mospf lsa part
                    lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
                    memcpy(lsa, lsa_packets, nbr_num * MOSPF_LSA_SIZE);
                    // update checksum of ip and mospf
                    mospf->checksum = mospf_checksum(mospf);
                    ip->checksum = ip_checksum(ip);
                    // send packet
                    ip_send_packet(packet, LSU_PACKET_LEN(nbr_num));
                }
            }
        }
    }
    free(lsa_packets);
}
```

* `void *sending_mospf_lsu_thread(void *param)`
    * 该函数用来定时发送lsu消息
        * 每隔`instance->lsuint`秒

代码如下：

```c
void *sending_mospf_lsu_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    while (1) {
        // printf("sending_mospf_lsu_thread.\n");
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list)
            if (!list_empty(&(iface->nbr_list)))
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list)
                    send_mospf_lsu();
        sleep(instance->lsuint);
    }
    return NULL;
}
```

* `void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)`
    * 该函数用来处理收到的lsu消息
    * 首先在本节点数据库中查询，是否有发送消息的节点：
        * 如果有，并且收到消息的序列号比数据库记录的大，则更新数据库；
        * 否则，建立新的数据库表项，并将相应数据（`lsa部分`）拷贝进该表项；
    * 接着，如果该消息的TTL值大于零，则继续向**本节点所有邻居**转发该消息：
        * 重新建立新的包，先将原包内容拷贝进去，然后修改ip header中的目的和源地址
            * `ip->saddr = htonl(iface->ip);`
            *  `ip->daddr = htonl(nbr_entry->nbr_ip);`
        * 在重新计算校验和，然后通过`ip_send_packet()`发送该网络包；
    * 其中，在转发消息时，注意以下一点：
        * 不把消息向发来的方向重新发送
        * `(nbr_entry->nbr_ip != ntohl(ip->saddr)  && nbr_entry->nbr_id != ntohl(mospf->rid)`

代码如下：

```c
void handle_mospf_lsu(iface_info_t *iface, char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    struct mospf_hdr * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_lsu * lsu   = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
    struct mospf_lsa * lsa   = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
    // search db, then update db if necessary
    int found = 0;
    pthread_mutex_lock(&mospf_lock);
    if (!list_empty(&(mospf_db))) {
        mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
            if (db_entry->rid == ntohl(mospf->rid)) {
                found = 1;
                if (db_entry->seq < ntohs(lsu->seq)) { 
                    // packet seq is bigger, update lsa
                    db_entry->rid  = ntohl(mospf->rid);
                    db_entry->seq  = ntohs(lsu->seq);
                    db_entry->nadv = ntohl(lsu->nadv);
                    for (int i = 0; i < db_entry->nadv; i++, lsa++) {
                        db_entry->array[i].subnet = ntohl(lsa->subnet);
                        db_entry->array[i].mask   = ntohl(lsa->mask);
                        db_entry->array[i].rid    = ntohl(lsa->rid);
                    }
                }
                break;
            }
        }
    }
    // db entry not found or db entry does not exist
    // create a new db entry
    if (!found) {
        mospf_db_entry_t * new_db_entry = 
            (mospf_db_entry_t *)malloc(MOSPF_DB_ENTRY_SIZE);
        new_db_entry->rid   = ntohl(mospf->rid);
        new_db_entry->seq   = ntohs(lsu->seq);
        new_db_entry->nadv  = ntohl(lsu->nadv);
        new_db_entry->array = 
            (struct mospf_lsa *)malloc((new_db_entry->nadv) * MOSPF_LSA_SIZE);
        for (int i = 0; i < new_db_entry->nadv; i++, lsa++) {
            new_db_entry->array[i].subnet = ntohl(lsa->subnet);
            new_db_entry->array[i].mask   = ntohl(lsa->mask);
            new_db_entry->array[i].rid    = ntohl(lsa->rid);
        }
        list_add_tail(&(new_db_entry->list), &mospf_db);
    }
    pthread_mutex_unlock(&mospf_lock);
    // if ttl > 0, forward this packet
    if ((lsu->ttl--) > 0) {
        // pre-declarations of variables
        char * out_packet = NULL;
        struct iphdr        * out_ip    = NULL;
        struct mospf_hdr    * out_mospf = NULL;
        iface_info_t * iface = NULL, * iface_q = NULL;
        mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
        // for each iface and its nbr forward the packet
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    if (nbr_entry->nbr_ip != ntohl(ip->saddr) 
                        && nbr_entry->nbr_id != ntohl(mospf->rid)) { 
                        // avoid sending packet back to source
                        out_packet = (char *)malloc(len);
                        if (!out_packet) {
                            printf("handle_mospf_lsu: out_packet malloc error.\n"); 
                            exit(-1);
                        }
                        memcpy(out_packet, packet, len);
                        // ATTENTION: ether header will be modified in ip_send_packet()
                        // change ip header
                        out_ip = packet_to_ip_hdr(out_packet);
                        out_ip->saddr = htonl(iface->ip);
                        out_ip->daddr = htonl(nbr_entry->nbr_ip);
                        // update checksum of ip and mospf header
                        out_mospf = (struct mospf_hdr *)
                                    ((char *)out_ip+IP_HDR_SIZE(out_ip));
                        out_mospf->checksum = mospf_checksum(out_mospf);
                        out_ip->checksum = ip_checksum(out_ip);
                        // send packet
                        ip_send_packet(out_packet, len);
                    }
                }
            }
        }
    }
}
```

