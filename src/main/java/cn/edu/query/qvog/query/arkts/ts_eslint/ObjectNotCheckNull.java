package cn.edu.query.qvog.query.arkts.ts_eslint;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.arkts.ArkTSQuery;
import cn.edu.query.qvog.query.cxx.misuse.locationProblem.forget.FileNotClose;

public class ObjectNotCheckNull extends ArkTSQuery{
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute("ObjectNotCheckNull", new ObjectNotCheckNull())
                .close();
    }

    public CompleteQuery run() {

    }
}
