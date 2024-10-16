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
 * 1. args too few
 * 2. without constant explain, 2nd arg
 */
public class FprintfArgs extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(FprintfArgs.class.getSimpleName(), new FprintfArgs())
                .execute(OpenArgs.class.getSimpleName(), new OpenArgs())
                .execute(PrintfArgs.class.getSimpleName(), new PrintfArgs())
                .execute(RsaSize.class.getSimpleName(), new RsaSize())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(
                        e -> e instanceof CallExpression callExpression &&
                                "fprintf".equals(callExpression.getFunction().getName()) &&
                                callExpression.getArgumentsSize() >= 2
                                        && callExpression.getArgumentAt(1) instanceof Literal format
                                        && format.getType() instanceof StringType
                                        && CxxQueryHelper.checkPrintfLikeLiteralLegal((String) format.getValue(),
                                        callExpression.getArguments().subList(2, callExpression.getArgumentsSize()))
                                ))
                .select("source");
    }
}
