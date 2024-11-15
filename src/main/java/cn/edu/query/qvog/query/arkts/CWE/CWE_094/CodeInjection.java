package cn.edu.query.qvog.query.arkts.CWE.CWE_094;

/*
import router from '@system.router';

@Entry
@Component
struct CodeExecution {
        build() {
        // 获取传入的代码作为字符串
        const code = router.getQueryParameter('code');

        // 执行传入的代码，可能导致代码注入漏洞
        eval(code); // NOT OK: 存在代码注入风险
        }
        }
*/

public class CodeInjection extends ArkTSQuery{
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new cn.edu.query.qvog.query.arkts.CWE.CWE_094.CodeInjection()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-094: Code Injection";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("input", new ContainsFunctionCall("router.getParams"), "router.getParams")
                .fromP("exec", new ContainsFunctionCall("eval").or(new ContainsFunctionCall("Function")))
                .where(TaintFlowPredicate.with()
                        .source("input")
                        .sink("exec")
                        .as("path").exists())
                .select("input", "exec", "path");
    }
}
