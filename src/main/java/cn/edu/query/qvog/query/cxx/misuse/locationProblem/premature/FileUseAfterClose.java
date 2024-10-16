package cn.edu.query.qvog.query.cxx.misuse.locationProblem.premature;

import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.CrossFunctionTaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.cxx.lib.ContainsFileUseFunction;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class FileUseAfterClose extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute("FileUseAfterClose", new FileUseAfterClose())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("fclose"))
                .from("sink", new ContainsFileUseFunction())
                .where(CrossFunctionTaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .as("path").exists())
                .select("source", "sink");
    }
}
