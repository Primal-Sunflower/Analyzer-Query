package cn.edu.query.qvog.query.arkts.CWE.CWE_215;

/*
import router from '@system.router';

@Entry
@Component
struct DebugApp {
  build() {
    // 启动应用并开启调试模式
    router.push({
      uri: 'pages/index',
      debug: true  // NOT OK: 调试模式启用，可能导致敏感信息泄露
    });
  }
}

 */

public class FlaskDebug extends ArkTSQuery {
    public static void main(String[] args){
        QueryEngine.getInstance().execute(new cn.edu.query.qvog.query.python.CWE_215.FlaskDebug()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-215 Flask Debug";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("router.push", new ContainsFunctionCall("router.pushUrl"), "router.pushUrl")
                .whereP(new ContainsFunctionCall(
                        call -> call.getArguments().stream().anyMatch(
                                arg -> arg instanceof NamedExpression expression &&
                                        expression.getExpression() instanceof Literal literal &&
                                        literal.getType() instanceof BoolType && literal.<Boolean>getTypedValue()),
                        "router.push"))
                .select("router.push", "ArkTS app run with debug mode enabled");
    }
}
