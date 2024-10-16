package cn.edu.query.qvog.query.cxx.misuse.locationProblem.forget;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.cxx.CxxDeleteExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.cxx.CxxNewExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.cxx.lib.ContainsCxxSystemExit;

public class MemoryNotDelete extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(MemoryNotDelete.class.getSimpleName(), new MemoryNotDelete())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(v -> v instanceof CxxNewExpression))
                .from("sink", value -> value.toStream().anyMatch(v -> v instanceof CxxDeleteExpression))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .addSysExitAsSink(true)
                        .specialSink(new ContainsCxxSystemExit())
                        .as("path").exists())
                .select("source");
    }
}
