package cn.edu.query.qvog.query.arkts.CWE.CWE_022;

public class TaintedPath extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new cn.edu.query.qvog.query.arkts.CWE.CWE_022.TaintedPath()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-022: Tainted Path";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("TextInput"), "TextInput")
                .from("sink", new ContainsFunctionCall("*.openSync"), "*.openSync")
                .fromP("barrier", value -> value.toStream().anyMatch(v -> v instanceof IfStatement))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .barrier("barrier")
                        .as("path").exists())
                .select("source", "sink", "path");
    }
}