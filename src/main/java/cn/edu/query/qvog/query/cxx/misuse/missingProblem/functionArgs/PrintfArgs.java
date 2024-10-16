package cn.edu.query.qvog.query.cxx.misuse.missingProblem.functionArgs;

import cn.edu.engine.qvog.engine.core.graph.types.StringType;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.query.qvog.query.cxx.misuse.CxxQueryHelper;

/**
 * the query finish two things:
 * 1. args size vs format size
 * 2. args type vs format type
 */
public class PrintfArgs extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(PrintfArgs.class.getSimpleName(), new PrintfArgs())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(
                        e -> e instanceof CallExpression callExpression &&
                                "printf".equals(callExpression.getFunction().getName()) &&
                                callExpression.getArguments().size() > 1 &&
                                        callExpression.getArguments().get(0) instanceof Literal format &&
                                        format.getType() instanceof StringType &&
                                        CxxQueryHelper.checkPrintfLikeLiteralLegal((String) format.getValue(),
                                                callExpression.getArguments().subList(1, callExpression.getArgumentsSize() - 1))
                ))
                .select("source");
    }
}
