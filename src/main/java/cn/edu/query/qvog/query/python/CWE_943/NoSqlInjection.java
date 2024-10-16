package cn.edu.query.qvog.query.python.CWE_943;

/*
CWE-943: NoSQL Injection

# Bad
@app.route("/")
def home_page_bad():
    unsanitized_search = request.args["search"]
    json_search = json.loads(unsanitized_search)
    result = mongo.db.user.find({"name": json_search})


# Good
@app.route("/")
def home_page_good():
    unsafe_search = request.args["search"]
    json_search = json.loads(unsafe_search)
    safe_search = sanitize(json_search)

    result = client.db.collection.find_one({"data": safe_search})
 */

import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.CallExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.dsl.lib.predicate.MatchAll;
import cn.edu.engine.qvog.engine.language.python.PythonQuery;
import cn.edu.engine.qvog.engine.language.python.lib.predicate.ContainsFunctionCall;

public class NoSqlInjection extends PythonQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new NoSqlInjection()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-943: NoSQL Injection";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", CallExpression.class)
                .fromP("barrier", new ContainsFunctionCall("sanitize"))
                .fromP("sink", new MatchAll())
                .where(p -> p.onTable("source")
                        .where(new ContainsFunctionCall("json.loads")))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .barrier("barrier")
                        .as("path").exists())
                .select("source", "sink", "path");
    }
}
