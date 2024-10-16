package cn.edu.query.qvog.query.cxx.misuse.missingProblem.functionArgs;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;

public class OpenArgs extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(OpenArgs.class.getSimpleName(), new OpenArgs())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(
                        epxr -> epxr instanceof CallExpression callExpression &&
                                "open".equals(callExpression.getFunction().getName()) &&
                                callExpression.getArgumentsSize() <= 2))
                .select("source");
    }
}
