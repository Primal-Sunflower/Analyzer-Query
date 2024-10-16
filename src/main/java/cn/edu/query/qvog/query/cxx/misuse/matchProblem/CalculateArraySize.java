package cn.edu.query.qvog.query.cxx.misuse.matchProblem;

import cn.edu.engine.qvog.engine.core.graph.values.statements.FunctionDefStatement;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.UnaryOperator;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;

public class CalculateArraySize extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute("CalculateArraySize", new CalculateArraySize())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value instanceof FunctionDefStatement)
                .from("sink", value -> value.toStream().anyMatch(
                        v -> v instanceof UnaryOperator unary &&
                                "sizeof".equals(unary.getOperator()) &&
                                !(unary.getOperand() instanceof Literal)))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .as("path").exists()
                ).select("source", "sink");
    }
}
