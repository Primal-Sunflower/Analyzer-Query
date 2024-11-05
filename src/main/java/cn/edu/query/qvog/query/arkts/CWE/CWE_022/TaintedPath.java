package cn.edu.query.qvog.query.arkts.CWE.CWE_022;

import cn.edu.engine.qvog.engine.core.graph.values.statements.IfStatement;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.arkts.ArkTSQuery;
import cn.edu.engine.qvog.engine.language.arkts.lib.predicate.ContainsFunctionCall;

public class TaintedPath extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new cn.edu.query.qvog.query.arkts.CWE.CWE_022.TaintedPath()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-022: Tainted Path";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("TextInput"), "TextInput")
                .from("sink", new ContainsFunctionCall("*.openSync"), "*.openSync")
                .fromP("barrier", value -> value.toStream().anyMatch(v -> v instanceof IfStatement))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .barrier("barrier")
                        .as("path").exists())
                .select("source", "sink", "path");
    }
}