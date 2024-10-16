# Analyzer-Query
代码静态分析器-query部分，原部分见https://github.com/QVoG-BUAA，

这里只是尝试迭代添加ArkTS部分

## 项目构建

该项目的构建依赖于 QVoG-Engine，需要将其构建生成的 `QVoGine-1.0.jar` 放置于项目下的 `lib` 目录。

在 IDEA 中，执行 `maven install` 来构建项目。生成的 jar 包将位于 `target` 目录中。

- 我们可以创建以下文件结构以在终端中运行

```text
config.json
QVoGine-1.0.jar
- lib
    - Query-1.0.jar
```

## 快速开始

### 命名格式

每种语言的查询都应放在 `query.<language>` 包下，`query` 外或 `language` 下可以有任意包，但 `query` 必须直接包含 `<language>`。

### 漏洞模式类

对于每一种漏洞模式，都需要编写独立的类代表一个查询规则。默认会以类名为查询名称，可以通过重载 `getQueryName()` 自定义查询名称。查询的核心逻辑位于 `run()` 方法内部。

```java
public class CustomQuery extends PythonQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new CustomQuery()).close();
    }

    @Override
    public String getQueryName() {
        return "A custom query";
    }
    
    @Override
    public CompleteQuery run() {
        // ...
    }
}
```

其中的 `main` 方法用于在编写时进行测试，如果要使用，则需要在项目根目录添加 `config.json`，具体格式见 QVoG-Executor。

### 查询编写

可以使用 Fluent API 编写查询，基本使用方式如下。

```java
@Override
public CompleteQuery run() {
    return QueryDesciptor.open()  // 开启一个查询
        .from("source", CallExpression.class)  // 选择所有包含 CallExpression 的节点作为 "source"
        .from("sink", new ContainsFunctionCall("open")) // 选择所有满足 Predicate 的节点作为 "sink"
        .fromP("barrier", value -> value.toStream()
             .anyMatch(v -> v instanceof IfStatement))  // 构造 "barrier" 需要满足的条件
        .where(TaintFlowPredicate.with()  // 开始构造一个 TaintFlowPredicate
             .source("source")     // 以 "source" 表为 Source
             .sink("sink")         // 以 "sink" 表为 Sink
             .barrier("barrier")   // 以 "barrier" 表为 Barrier
             .as("path")           // 将路径结果存储在表 "path" 中的 "source", "sink", "path" 列
             .exists())            // 返回构造的 FlowPredicate
        .select("source", "sink", "path");     // 选择表中的 "source"，"sink"，"path" 列
}
```

可能的输出如下。

| source                                        | sink                                                         | path     |
| --------------------------------------------- | ------------------------------------------------------------ | -------- |
| (prod.py:59) filename = request.args.get('p') | (prod.py:61) data = open(filename, 'rb').read()              | 59 -> 61 |
| (prod.py:67) filename = request.args.get('p') | (prod.py:69) data = open(os.path.join(base_path, filename), 'rb... | 67 -> 69 |

## 高级查询编写

### from

from 的语义是从图数据库中选择指定的数据，组成一张表（`ITable`）。from 可以串联，从而得到多张表的集合（`ITableSet`）。

每一个 `from` 语句都代表了一张表，类型为 `DataTable`，但有两种内容，一种是一般的 `DataColumn`，另一种是 `PredicateColumn`。`DataColumn` 包含数据，而 `PredicateColumn` 则是通过 `Predicate` 来判断元素是否在表中。

每张表都包含且只包含一列，表名和列名相同，都为 `from` 的 `alias` 参数。

> 你可以通过 `fromP` 得到含 `PredicateColumn` 的表。

From 得到的表均启用索引，能够快速判断元素是否在表中。

> 在 from 中，你可以手动指定 `cacheTag`，从而将其缓存。

### where

where 的语义是从 from 得到的表中，进行筛选或者组合。

#### Filter where

> 相关类位于 `cn.edu.query.qvog.engine.dsl.fluent.filter` 包下。

对某一张表进行筛选，其核心为 `IFilterPredicate`，一般用法如下。可以在使用处构造 `IFilterPredicate`，其使用 `IRowPredicate` 对每一行进行判断，而后者又可以使用 `IValuePredicate` 对行中的列进行判断。

```java
QueryDescriptor.open()
    .from("call", CallExpression.class)
    .where(q -> q.onTable("call")                     // 对 "call" 表进行筛选
           .where(new ContainsFunctionCall("app.run") // 值满足某 predicate
                  .onColumn("call")))                 // 在 "call" 列使用 Predicate
    .select("call", "Flask app run found!")
    .display();
```

当查询比较简单，即只有一个 `from` 时，可以简化 `where` 的编写。

```java
QueryDescriptor.open()
    .from("call", CallExpression.class)
    .where(q -> q.onTable("call")                       // 对 "call" 表进行筛选
           .where(new ContainsFunctionCall("app.run"))) // 表中唯一的列的值满足某 predicate
    .select("call", "Flask app run found!")
    .display();
```

也可以直接简化为使用一个 `IValuePredicate`，这时需要使用 `whereP` 方法。

```java
QueryDescriptor.open()
    .from("call", CallExpression.class)
    .whereP(new ContainsFunctionCall("app.run")) // 唯一的表的唯一的列的值满足某 predicate
    .select("call", "Flask app run found!")
    .display();
```

#### Join where

> 相关接口位于 `cn.edu.query.qvog.engine.dsl.fluent.flow`，相关类位于 `cn.edu.query.qvog.engine.dsl.lib.flow`。

对多张表进行可达性判断（流分析），并合成一张表。目前支持了普通的 Data Flow，Control Flow 以及 Taint Flow，底层的遍历支持 DFS，哈密顿通路和欧拉通路三种方式。其核心是 `IFlowPredicate`。

流的基本实现方式如下，不同 `IFlowPredicate` 的实现有所差异。

1. 获取 Source、Sink、Barrier 对应的表。
2. 分别以 Source 中的每一个 `Vaule` 进行遍历，如能够不经过 Barrier 到达 Sink，则将 Source、Sink 和 Path 添加到结果表中。

> Source 必须是包含 `DataColumn`，不能是包含 `PredicateColumn` 的表。Barrier 和 Sink 无限制。

若省略 Barrier，则默认所有节点都**不是** Barrier；若省略 Sink，则默认所有节点都**是** Sink。

在使用 `FlowPredicate` 后，会从 From 得到的表中移除指定的 Source、Sink 和 Barrier 表，并添加一张新表，由 `as` 指定其名称，表中的列名即为原本的表名，表中路径的列明与表名相同。例如，对于如下的查询，

```java
QueryDescriptor.open()
                .from("input", new ContainsFunctionCall("request.*"))
                .fromP("exec", new ContainsFunctionCall("exec").or(new ContainsFunctionCall("eval")))
                .where(TaintFlowPredicate.with()
                        .source("input")
                        .sink("exec")
                        .as("path").exists())
                .select("input", "exec", "path")
                .display();
```

其可能输出结果如下。

| input                                        | exec                    | path           |
| -------------------------------------------- | ----------------------- | -------------- |
| (prod.py:92) code = request.args.get('code') | (prod.py:93) exec(code) | 92 -> 93       |
| (prod.py:92) code = request.args.get('code') | (prod.py:94) eval(code) | 92 -> 93 -> 94 |

### select

Select 即为按顺序从 from 和 where 得到的结果中选取指定列。只有当查询中只存在一张表时可以使用 select，否则需要用 `IFlowPredicate` 进行 Join。

