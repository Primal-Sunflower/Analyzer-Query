package cn.edu.query.qvog.query.arkts.performanceRule;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.arkts.ArkTSQuery;

public class ForEachThirdArgMissing extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(ForEachThirdArgMissing.class.getSimpleName(), new ForEachThirdArgMissing())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(
                        epxr -> epxr instanceof CallExpression callExpression &&
                                "ForEach".equals(callExpression.getFunction().getName()) &&
                                callExpression.getArgumentsSize() == 2))
                .select("source");
    }
}
