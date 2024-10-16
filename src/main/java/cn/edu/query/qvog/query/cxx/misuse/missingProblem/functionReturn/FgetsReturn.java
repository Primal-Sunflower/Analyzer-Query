package cn.edu.query.qvog.query.cxx.misuse.missingProblem.functionReturn;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.AssignExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.HighPrecisionTaintFlow;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

/**
 * @see FunctionReturnCheck
 * @deprecated
 */
public class FgetsReturn extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(FgetsReturn.class.getSimpleName(), new FgetsReturn())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("fgets"))
                .from("barrier", expr -> expr instanceof IfStatement)
                .from("sink", e -> e instanceof CallExpression || e instanceof AssignExpression)
                .where(HighPrecisionTaintFlow.with()
                        .source("source")
                        .barrier("barrier")
                        .sink("sink")
                        .as("path").exists())
                .select("source", "sink");
    }
}
