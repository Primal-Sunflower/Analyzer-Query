package cn.edu.query.qvog.query.cxx.misuse.locationProblem.premature;

import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.cxx.lib.ContainsMemoryAllocFunction;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class UseAfterFree extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(UseAfterFree.class.getSimpleName(), new UseAfterFree())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("free"))
                .from("barrier", new ContainsMemoryAllocFunction())
                .from("sink", new ContainsFunctionCall("printf"))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .barrier("barrier")
                        .sink("sink")
                        .as("path").exists())
                .select("source", "sink");
    }
}
