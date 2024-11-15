package cn.edu.query.qvog.query.arkts.CWE.CWE_798;

public class HardcodedCredentials extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new HardcodedCredentials()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-798: Hardcoded Credentials";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                // Step 1: 查找硬编码的敏感信息
                .from("hardcodedCredential", new ContainsFunctionCall("const").or(new ContainsFunctionCall("let")), "assignment")
                .whereP(new ContainsFunctionCall(
                        call -> call.getArguments().stream().anyMatch(
                                arg -> arg instanceof NamedExpression expression &&
                                        expression.getExpression() instanceof Literal literal &&
                                        literal.getType() instanceof StringType && (
                                        literal.getTypedValue().toLowerCase().contains("password") ||
                                                literal.getTypedValue().toLowerCase().contains("key"))),
                        "hardcodedCredential"))

                // Step 2: 查找是否存在输出或页面展示的场景
                .fromP("output", new ContainsFunctionCall("console.log").or(new ContainsFunctionCall("router.push")), "output")

                // Step 3: 检测敏感信息是否传递给输出/展示
                .where(TaintFlowPredicate.with()
                        .source("hardcodedCredential")
                        .sink("output")
                        .as("path").exists())

                // 选择查询结果
                .select("hardcodedCredential", "output", "path");
    }
}


