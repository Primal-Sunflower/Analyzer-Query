package cn.edu.query.qvog.query.cxx.misuse.missingProblem.overflowCheck;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class Sprintf extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new Sprintf()).close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("scanf"))
                .from("barrier", e -> e instanceof IfStatement)
                .from("sink", new ContainsFunctionCall("sprintf"))
                .where(TaintFlowPredicate.with().barrier("barrier").as("path").exists())
                .select("source", "sink");
    }
}
