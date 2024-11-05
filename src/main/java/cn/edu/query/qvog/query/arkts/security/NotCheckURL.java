package cn.edu.query.qvog.query.arkts.security;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.arkts.ArkTSQuery;
import cn.edu.engine.qvog.engine.language.arkts.lib.predicate.ContainsFunctionCall;
import cn.edu.query.qvog.query.arkts.ArkTSQueryHelper;
import cn.edu.query.qvog.query.arkts.ts_eslint.ObjectNotCheckNull;
import cn.edu.query.qvog.query.cxx.misuse.CxxQueryHelper;

public class NotCheckURL extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute("NotCheckURL", new NotCheckURL())
                .close();
    }

    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new MatchAll(), "URL")
                .from("sink", new ContainsFunctionCall("*.redirect"), "*.redirect")
                .fromP("barrier", value -> value.toStream().anyMatch(v -> v instanceof IfStatement))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .barrier("barrier")
                        .as("path").exists())
                .select("source", "sink", "path");
    }
}
