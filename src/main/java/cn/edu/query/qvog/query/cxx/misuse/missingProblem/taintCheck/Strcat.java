package cn.edu.query.qvog.query.cxx.misuse.missingProblem.taintCheck;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.HighPrecisionTaintFlow;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class Strcat extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(Strcat.class.getSimpleName(), new Strcat())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("scanf"))
                .from("barrier", v -> v instanceof IfStatement)
                .from("sink", new ContainsFunctionCall("strcat"))
                .where(HighPrecisionTaintFlow.with()
                        .source("source")
                        .barrier("barrier")
                        .sink("sink")
                        .as("path").exists())
                .select("source", "sink");
    }
}
