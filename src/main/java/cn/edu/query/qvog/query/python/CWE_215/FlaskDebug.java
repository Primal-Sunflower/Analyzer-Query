package cn.edu.query.qvog.query.python.CWE_215;

import cn.edu.engine.qvog.engine.core.graph.types.BoolType;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.Literal;
import cn.edu.engine.qvog.engine.core.graph.values.statements.expressions.NamedExpression;
import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.language.python.PythonQuery;
import cn.edu.engine.qvog.engine.language.python.lib.predicate.ContainsFunctionCall;

/*
############################################################
# CWE-215 Flask Debug Mode

from flask import Flask

app = Flask(__name__)


@app.route("/crash")
def main():
    raise Exception()


app.run(debug=True)
 */
public class FlaskDebug extends PythonQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new FlaskDebug()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-215 Flask Debug";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("app.run", new ContainsFunctionCall("app.run"), "app.run")
                .whereP(new ContainsFunctionCall(
                        call -> call.getArguments().stream().anyMatch(
                                arg -> arg instanceof NamedExpression expression &&
                                        expression.getExpression() instanceof Literal literal &&
                                        literal.getType() instanceof BoolType && literal.<Boolean>getTypedValue()),
                        "app.run"))
                .select("app.run", "Flask run with debug mode enabled");
    }
}
