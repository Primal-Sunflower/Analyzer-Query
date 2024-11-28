package cn.edu.query.qvog.query.arkts.CWE.CWE_022;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.arkts.ArkTSQuery;
import cn.edu.engine.qvog.engine.language.arkts.lib.predicate.ContainsFunctionCall;


/*
import { fileIo as fs, ReadOptions } from '@kit.CoreFileKit';
import { buffer } from '@kit.ArkTS';

@Entry
@Component
struct Index {
  @State path: string = "";

  private operateFiles() {

  // 不写这个if就是含有漏洞
    if(!this.path || this.path.includes("..") || this.path.startsWith("/")) {
      console.error("路径不合法");
      return;
    }


    let file = fs.openSync(this.path + "/111.txt", fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE);
    fs.writeSync(file.fd, "你好");
    let arrayBuffer = new ArrayBuffer(1024);
    let readOptions: ReadOptions = {
      offset: 0,
      length: arrayBuffer.byteLength
    };
    let readLen = fs.readSync(file.fd, arrayBuffer, readOptions);
    let buf = buffer.from(arrayBuffer, 0, readLen);
    console.info("文件的内容是" + buf);
  }

  build() {
    Column() {
      TextInput({placeholder:"请输入文件路径"})
        .onChange((value) => this.path = value)

      Button("操作文件")
        .onClick(() => this.operateFiles())
        .margin({ top: 20 })
    }
    .width('100%')
    .height('100%')
  }
}



 */


public class TaintedPath extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new cn.edu.query.qvog.query.arkts.CWE.CWE_022.TaintedPath()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-022: Tainted Path";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("TextInput"), "TextInput")
                .from("sink", new ContainsFunctionCall("*.readSync").or(new ContainsFunctionCall("*.writeSync")))
                .fromP("barrier", value -> value.toStream().anyMatch(v -> v instanceof IfStatement))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .barrier("barrier")
                        .as("path").exists())
                .select("source", "sink", "path");
    }
}