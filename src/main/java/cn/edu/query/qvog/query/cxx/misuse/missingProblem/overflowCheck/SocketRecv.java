package cn.edu.query.qvog.query.cxx.misuse.missingProblem.overflowCheck;

import cn.edu.engine.qvog.engine.core.graph.types.IntegerType;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.query.qvog.query.cxx.misuse.CxxQueryHelper;

public class SocketRecv extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new SocketRecv()).close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", v -> v.toStream().anyMatch(e -> e instanceof CallExpression fc
                        && "recv".equals(fc.getFunction().getName())
                        && fc.getArgumentsSize() == 4
                        && fc.getArguments().get(2) instanceof Literal literal
                        && literal.getType() instanceof IntegerType
                        && !CxxQueryHelper.compareTypeSize(
                        (Long) literal.getValue(), fc.getArgumentAt(1).getType())))
                .select("source");
    }
}
