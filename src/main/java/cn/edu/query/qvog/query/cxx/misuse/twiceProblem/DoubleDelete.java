package cn.edu.query.qvog.query.cxx.misuse.twiceProblem;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.cxx.CxxDeleteExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.cxx.CxxNewExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.CrossFunctionTaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsDefineLikeOperation;

public class DoubleDelete extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(DoubleDelete.class.getSimpleName(), new DoubleDelete())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(v -> v instanceof CxxDeleteExpression))
                .from("barrier", new ContainsDefineLikeOperation()
                        .or(value -> value.toStream().anyMatch(v -> v instanceof CxxNewExpression)))
                .from("sink", value -> value.toStream().anyMatch(v -> v instanceof CxxDeleteExpression))
                .where(CrossFunctionTaintFlowPredicate.with()
                        .source("source")
                        .barrier("barrier")
                        .sink("sink")
                        .as("path").exists())
                .select("source", "sink");
    }
}
