package cn.edu.query.qvog.query.java.lib;

import cn.edu.engine.qvog.engine.core.graph.values.Value;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.BinaryOperator;
import cn.edu.engine.qvog.engine.dsl.lib.predicate.IValuePredicate;

public class IntegerIncrease implements IValuePredicate {
    @Override
    public boolean test(Value value) {
        return value.toStream().anyMatch(v -> {
            if (v instanceof BinaryOperator op) {
                return op.getOperator().equals("+") || op.getOperator().equals("*");
            }
            return false;
        });
    }
}
