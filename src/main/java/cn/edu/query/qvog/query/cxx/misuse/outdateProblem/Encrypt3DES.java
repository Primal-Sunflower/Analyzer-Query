package cn.edu.query.qvog.query.cxx.misuse.outdateProblem;

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;

public class Encrypt3DES extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(Encrypt3DES.class.getSimpleName(), new Encrypt3DES())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", v -> v.toStream().anyMatch(
                        call -> call instanceof CallExpression expression &&
                                expression.getArgumentsSize() >= 2 &&
                                expression.getArgumentAt(1) instanceof Literal literal &&
                                "CALG_3DES".equals(literal.getValue())))
                .select("source");
    }
}
