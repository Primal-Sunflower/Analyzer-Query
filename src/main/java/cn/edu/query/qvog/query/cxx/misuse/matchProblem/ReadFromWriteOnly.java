package cn.edu.query.qvog.query.cxx.misuse.matchProblem;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Expression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class ReadFromWriteOnly extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(ReadFromWriteOnly.class.getSimpleName(), new ReadFromWriteOnly())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall(
                        call -> {
                            if (call.getArgumentsSize() < 2) {
                                return false;
                            }
                            Expression descriptor = call.getArgumentAt(1);
                            if (descriptor instanceof Literal literal) {
                                return literal.getValue().equals("w");
                            }
                            return false;
                        },
                        "fopen"))
                .from("sink", new ContainsFunctionCall("fgets"))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .as("path").exists())
                .select("source", "sink");
    }
}
