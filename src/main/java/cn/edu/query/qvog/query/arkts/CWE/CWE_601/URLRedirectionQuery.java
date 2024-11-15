package cn.edu.query.qvog.query.arkts.CWE.CWE_601;

import cn.edu.query.qvog.query.arkts.CWE.ArkTSQuery;
import cn.edu.query.qvog.query.arkts.CWE.CompleteQuery;
import cn.edu.query.qvog.query.arkts.CWE.QueryDescriptor;
import cn.edu.query.qvog.query.arkts.CWE.TaintFlowPredicate;
import cn.edu.query.qvog.query.arkts.CWE.ContainsFunctionCall;

public class URLRedirectionQuery extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new cn.edu.query.qvog.query.arkts.CWE.CWE_601.URLRedirectionQuery()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-601: URL Redirection to Untrusted Site";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("TextInput.getValue"), "TextInput.getValue")
                .from("sink", new ContainsFunctionCall("pushUrl"), "pushUrl")
                .fromP("barrier", value -> value.toStream().anyMatch(v -> v instanceof IfStatement))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .barrier("barrier")
                        .as("redirectPath").exists())
                .select("source", "sink", "redirectPath");
    }
}
