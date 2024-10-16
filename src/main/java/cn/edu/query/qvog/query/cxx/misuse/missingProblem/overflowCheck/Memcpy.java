package cn.edu.query.qvog.query.cxx.misuse.missingProblem.overflowCheck;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.InverseControlAndCgFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.query.qvog.query.cxx.misuse.CxxQueryHelper;

public class Memcpy extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(Memcpy.class.getSimpleName(), new Memcpy())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", v -> v.toStream().anyMatch(e -> e instanceof CallExpression fc
                        && "memcpy".equals(fc.getFunction().getName())
                        && fc.getArgumentsSize() == 3
                        && !CxxQueryHelper.compareTypeSize(
                        fc.getArguments().get(1).getType(),
                        fc.getArguments().get(0).getType())))
                .from("sink", v -> v instanceof IfStatement)
                .where(InverseControlAndCgFlowPredicate.builder()
                        .source("source")
                        .sink("sink")
                        .addFunctionEntryAsSink(true)
                        .as("path").exists()
                )
                .select("source");
    }
}
