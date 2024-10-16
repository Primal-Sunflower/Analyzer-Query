package cn.edu.query.qvog.query.cxx.misuse.matchProblem;

import cn.edu.engine.qvog.engine.core.graph.types.PointerType;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Reference;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.UnaryOperator;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsBinaryOperator;

public class CalculateArrayOffset extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute("CalculateArrayOffset", new CalculateArrayOffset())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsBinaryOperator(
                        expression -> expression instanceof Reference reference
                                && reference.getType() instanceof PointerType,
                        value -> value.toStream().anyMatch(
                                v -> v instanceof UnaryOperator unary &&
                                        "sizeof".equals(unary.getOperator()) &&
                                        unary.getOperand() instanceof Literal),
                        null))
                .select("source");
    }
}
