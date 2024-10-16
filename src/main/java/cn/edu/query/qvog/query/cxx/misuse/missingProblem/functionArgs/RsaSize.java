package cn.edu.query.qvog.query.cxx.misuse.missingProblem.functionArgs;

import cn.edu.engine.qvog.engine.core.graph.types.IntegerType;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;

public class RsaSize extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(RsaSize.class.getSimpleName(), new RsaSize())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", value -> value.toStream().anyMatch(
                        e -> e instanceof CallExpression callExpression &&
                                "EVP_PKEY_CTX_set_rsa_keygen_bits".equals(callExpression.getFunction().getName()) &&
                                callExpression.getArguments().size() == 2 &&
                                callExpression.getArguments().get(1) instanceof Literal buffer &&
                                buffer.getType() instanceof IntegerType &&
                                (Long) buffer.getValue() < 2048
                ))
                .select("source");
    }
}
