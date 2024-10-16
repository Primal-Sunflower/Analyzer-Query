package cn.edu.query.qvog.query.cxx.misuse.locationProblem.premature;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.cxx.CxxDeleteExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.CrossFunctionTaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;

public class UseAfterDelete extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(UseAfterDelete.class.getSimpleName(), new UseAfterDelete())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", e -> e.toStream().anyMatch(v -> v instanceof CxxDeleteExpression))
                .from("sink", e -> true)
                .where(CrossFunctionTaintFlowPredicate.with()
                        .as("path").exists())
                .select("source", "sink");
    }
}
