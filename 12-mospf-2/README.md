# 实验12 · 网络路由实验二

#### 吴嘉皓 2015K8009915007

## 一、实验内容

基于`11-mospf`的代码框架，实现路由器**计算路由表项**的相关操作：

  1. 将得到的一致性数据库抽象成拓扑图(Graph)；
  2. 在得到的拓扑图上使用**Dijkstra算法**计算源节点到其他节点的最短路径和相应的前一跳节点；
  3. 根据**2.**中得到的结果，生成路由表；


## 二、实验流程

### （一）代码目录

```bash
2015K8009915007_吴嘉皓_12.tar.gz
		├── 12-mospf-2  # 代码工程目录
		└──实验12-网络路由实验二·实验报告.pdf
```

### （二）测试流程

在 `12-mospf-2`目录下输入如下命令：

```bash
make
sudo python topo.py
mininet> xterm h1
h1> # 静待15s，输入如下命令
h1> traceroute 10.0.6.22
mininet> link r2 r4 down
h1> # 静等30s，输入如下命令
h1> traceroute 10.0.6.22
```

## 三、实验结果

* 本次实验的拓扑图

![image-20180601082234931](/Users/apple/Learning/CS/CN/Lab/12/1.png)

* 实验结果图
  * 完整链路的`traceroute`的结果(存在两种结果)

  ![2](/Users/apple/Learning/CS/CN/Lab/12/2.png)

  ![image-20180601083502254](/Users/apple/Learning/CS/CN/Lab/12/4.png)

  * `link r2 r4 down`之后的`traceroute`的结果

  ![3](/Users/apple/Learning/CS/CN/Lab/12/3.png)

## 四、结果分析

### （一）实验结果分析

* 完整链路的情况下，会产生两种`traceroute`的结果：

  * 10.0.0.1 `->` 10.0.2.2 `->` 10.0.4.4 `->` 10.0.6.22
  * 10.0.0.1 `->` 10.0.3.3 `->` 10.0.5.4 `->` 10.0.6.22

    因为我在写数据库到graph的转换时，把每一条边的权重都定为1，

    所以根据`Dijkstra算法`会存在以下两种路径：

①

  ```mermaid
  graph LR
  	A(Router 1) -->B(Router 2)
  	A -->C(Router 3)
      B -->D(Router 4)
  ```
②
  ```mermaid
  graph LR
  	A(Router 1) -->B(Router 2)
  	A -->C(Router 3)
      C -->D(Router 4)
  ```

* 在`link r2 r4 down`之后

  * 原本链路中，r2和r4之间的链路断开；

  * 因此，相应一致性数据库的lsa表项会发生改变（以`r4`为例）

    * 完整链路状态下的数据库如下：

      ![image-20180601085503634](/Users/apple/Learning/CS/CN/Lab/12/6.png)

    * 断开r2和r4之后的数据库如下：

      ![image-20180601085434877](/Users/apple/Learning/CS/CN/Lab/12/5.png)

  * 由上述的数据库打印信息可知，在断开`r2`和`r4`之后，数据库中r2的邻居为r4的表项已经不存在了

  * 于是，相应的graph也会变化。

  * 由于我们是根据graph来生成路由表表项的，因此，生成的路由表表项也会发生变化；

  * 这使得最终的结果只能有**图②**这一种。

### （二）代码实现分析
* `void *generating_mospf_rtable(void *param)`

  * 函数功能：每隔5秒根据一致性数据库生成对应的路由表表项；

  ``` C
  void *generating_mospf_rtable(void *param){
    while(1){
        sleep(5);
        database2rtable();        // 本次实验的主要函数，以下会解析
        printf("================ Print Rtable =================\n");
        print_rtable();
    }
    return NULL;
  }
  ```

* `void database2rtable()`

  * 函数功能：根据生成的一致性数据库生成对应的路由表表项；
  * 该函数为此次试验的主要函数；

  ``` c
  void database2rtable() {
      int num = database2graph();  // 将数据库转化为拓扑图
      caculate_shortest_path(num); // 计算最短路径(Dijkstra算法)
      path2rtable(num);			 // 将最短路径转化为路由表
  }
  ```

* `int database2graph()`
  * 函数功能：将生成的一致性数据库转换为拓扑图的邻接矩阵表示；
    * 根据数据库中的lsa（邻居）来确定两个路由节点是否相邻；
  * 返回值：`int`型变量，返回的是路由节点的个数；

  ```c
  int database2graph() {
    int num = 0, x = -1, y = -1;
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    init_graph();
    num2id[num++] = instance->router_id;
    if (!list_empty(&mospf_db)) {
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list)
            num2id[num++] = db_entry->rid;
    } else
        printf("Database is currently empty.\n");
    if (!list_empty(&mospf_db)) {
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
            for (int i = 0; i < db_entry->nadv; i++) {
                x = id2num(db_entry->array[i].rid, num);
                y = id2num(db_entry->rid, num);
                graph[x][y] = 1;
                graph[y][x] = 1;
            }
        }
    }
    return num;
  }
  ```

* `void caculate_shortest_path(int num)`
  * 函数功能：计算对应拓扑图的最短路径；（`Dijkstra算法`）
  * 输入参数：`int`型变量，为路由节点的个数；
  ``` c++
  #define NEED_UPDATE_PATH(visited,graph,dist,u,v) \
  ((visited[v] == false) && \
   (graph[u][v] > 0)     && \
   (dist[u] != INT_MAX)  && \
   (dist[u] + graph[u][v] < dist[v]))
  
  void caculate_shortest_path(int num) {
      for (int i = 0; i < num; i++) {
          visited[i] = false;
          dist[i] = graph[0][i];
          if (dist[i] == INT_MAX || dist[i] == 0)
              prev[i] = -1;
          else
              prev[i] = 0;
      }
      dist[0] = 0;
      visited[0] = true;
      int u = 0;
      for (int i = 0; i < num - 1; i++) {
          u = min_dist(num);
          visited[u] = true;
          for (int v = 0; v < num; v++) {
              if (NEED_UPDATE_PATH(visited, graph, dist, u, v)) {
                  dist[v] = dist[u] + graph[u][v];
                  prev[v] = u;
              }
          }
      }
  }
  ```

* `void path2rtable(int num)`

  * 函数功能：根据生成的最短路径生成路由表；
    * 对已经生成的`dist`进行升序排序；
    * 从小到大遍历路由节点：
      * 根据`prev`数组，得到源节点到该节点的**下一跳节点**的节点id；
      * 调用`get_iface_and_gw`来确定gw和iface；
      * 生成新的路由表表项，并添加至路由表；
  * 函数参数：`int`型，为路由节点的个数；

  ``` c
  void path2rtable(int num) {
      int hop = -1, s = 0;
      // sort dist as up order
      int sorted[num], bak[num];
      for(int i = 0; i < num; i++) sorted[i] = i;
      memcpy(bak, dist, num * sizeof(int));
      for (int i = 0; i < num - 1; i++)
          for (int j = 0; j < num - 1 - i; j++)
              if (bak[j] > bak[j+1]) {
                  swap(&(sorted[j]), &(sorted[j+1]));
                  swap(&(bak[j]), &(bak[j+1]));
              }
      // translate path to router table
      // Since local rtable has been loaded from kernel already,
      // we do not need to generate it again.
      // Thus, we focus on translate path to rt_entry, pointing to other routers.
      iface_info_t *iface = NULL;
      rt_entry_t * new_entry = NULL;
      mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
      u32 gw = 0, dest = 0;
      for (int i = 0; i < num; i++) {
          if (prev[sorted[i]] != -1) {
              if (!list_empty(&mospf_db))
                  list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list){
                      for (int j = 0; j < db_entry->nadv; j++)
                          if (!is_in_rtable(db_entry->array[j].subnet)) {
                              dest = db_entry->array[j].subnet;
                              hop = id2num(db_entry->rid, num);
                              while(prev[hop] != s)
                                  hop = prev[hop];
                              iface = get_iface_and_gw(num2id[hop], &gw);
                              new_entry = new_rt_entry(dest, iface->mask, gw, iface);
                              add_rt_entry(new_entry);
                          }
                  }
          }
      }
  }
  ```

* `iface_info_t *get_iface_and_gw(u32 rid, u32 *gw)`

  * 函数功能：根据提供的`rid`来确定与之对应的`gw`和`iface`
    * 遍历本节点iface列表及其邻居列表
    * 当邻居rid和传入rid相同时，匹配
    * 将gw设置为该邻居的ip

  ``` C
  iface_info_t *get_iface_and_gw(u32 rid, u32 *gw) {// get forward iface
    int is_connected = 0;
    iface_info_t *iface = NULL;
    mospf_nbr_t *nbr = NULL, *nbr_q = NULL;
    list_for_each_entry(iface, & (instance->iface_list), list) {
        list_for_each_entry_safe(nbr, nbr_q, &(iface->nbr_list), list) {
            if (nbr->nbr_id == rid) {
                is_connected = 1;
                *gw = nbr->nbr_ip;
                break;
            }
        }
        if (is_connected) break;
    }
    return iface;
  }
  ```

* `void *checking_database_thread(void * param)`
  * 函数功能：数据库表项的老化线程
    * 如果数据库表项超过20秒没有改动，则将其删去，并清空路由表；  
  ```c
void *checking_database_thread(void * param) {
    time_t now = 0;
    rt_entry_t * rt_entry = NULL, * rt_entry_q = NULL;
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    while (1) {
        if (!list_empty(&mospf_db)) {
            pthread_mutex_lock(&mospf_lock);
            now = time(NULL);
            list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) 
                if((now-db_entry->alive) >= 20){
                    list_for_each_entry_safe(rt_entry, rt_entry_q, &rtable, list) 
                        if(rt_entry->gw != 0)
                            remove_rt_entry(rt_entry);
                    free(db_entry->array);
                    list_delete_entry(&(db_entry->list));
                }
            pthread_mutex_unlock(&mospf_lock);
        } else
            printf("Database is now empty.\n");
        sleep(1);
    }
    return NULL;
}
  ```







