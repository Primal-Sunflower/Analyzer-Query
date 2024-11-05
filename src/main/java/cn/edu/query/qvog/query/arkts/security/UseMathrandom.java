package cn.edu.query.qvog.query.arkts.security;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.arkts.ArkTSQuery;
import cn.edu.engine.qvog.engine.language.arkts.lib.predicate.ContainsFunctionCall;
import cn.edu.query.qvog.query.arkts.ts_eslint.ObjectNotCheckNull;
import cn.edu.query.qvog.query.cxx.misuse.CxxQueryHelper;

public class UseMathrandom extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute("UseMathrandom", new UseMathrandom())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(
                        e -> e instanceof CallExpression callExpression &&
                                "Math.random".equals(callExpression.getFunction().getName()))
                )
                .select("source");
    }
}
