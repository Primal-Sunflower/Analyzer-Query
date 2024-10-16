package cn.edu.query.qvog.query.python.CWE_094;

import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.python.PythonQuery;
import cn.edu.engine.qvog.engine.language.python.lib.predicate.ContainsFunctionCall;

/*
from flask import Flask, request
app = Flask(__name__)

@app.route("/code-execution")
def code_execution():
    code = request.args.get("code")
    exec(code) # NOT OK
    eval(code) # NOT OK
 */
public class CodeInjection extends PythonQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new CodeInjection()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-094: Code Injection";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("input", new ContainsFunctionCall("request.*"), "request.*")
                .fromP("exec", new ContainsFunctionCall("exec").or(new ContainsFunctionCall("eval")))
                .where(TaintFlowPredicate.with()
                        .source("input")
                        .sink("exec")
                        .as("path").exists())
                .select("input", "exec", "path");
    }
}
