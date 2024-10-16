package cn.edu.query.qvog.query.java.lib;

import cn.edu.engine.qvog.engine.core.graph.types.IntegerType;
import cn.edu.engine.qvog.engine.core.graph.values.Value;
import cn.edu.engine.qvog.engine.core.graph.values.statements.DeclarationStatement;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.AssignExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.dsl.lib.predicate.IValuePredicate;

public class MaxIntegerDeclOrAssign implements IValuePredicate {
    @Override
    public boolean test(Value value) {
        if (value instanceof DeclarationStatement stmt && stmt.hasValue()) {
            Value v = stmt.getValueAt(0);
            if (v instanceof Literal literal) {
                return testLiteral(literal);
            }
        } else if (value instanceof AssignExpression expr) {
            var v = expr.getValue();
            if (v instanceof Literal literal) {
                return testLiteral(literal);
            }
        }

        return false;
    }

    private boolean testLiteral(Literal literal) {
        if (literal.getType() instanceof IntegerType) {
            if (literal.getValue() instanceof Integer value) {
                return value == Integer.MAX_VALUE;
            } else if (literal.getValue() instanceof Long value) {
                return value == Integer.MAX_VALUE;
            }
        }
        return false;
    }
}
