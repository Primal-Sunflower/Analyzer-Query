package cn.edu.query.qvog.query.cxx.misuse.outdateProblem;

import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.cxx.lib.ContainsCxxSystemExit;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class FunctionLastUseOptimize extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(FunctionLastUseOptimize.class.getSimpleName(), new FunctionLastUseOptimize())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("bzero")
                        .or(new ContainsFunctionCall("memset")))
                .from("sink", value -> true)
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .addSysExitAsSink(true)
                        .specialSink(new ContainsCxxSystemExit())
                        .as("path").exists())
                .select("source", "sink");
    }
}
