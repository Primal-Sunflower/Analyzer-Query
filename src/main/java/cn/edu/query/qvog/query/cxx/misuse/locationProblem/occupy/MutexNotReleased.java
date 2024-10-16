package cn.edu.query.qvog.query.cxx.misuse.locationProblem.occupy;

import cn.edu.engine.qvog.engine.dsl.fluent.query.CompleteQuery;
import cn.edu.engine.qvog.engine.dsl.fluent.query.QueryDescriptor;
import cn.edu.engine.qvog.engine.dsl.lib.engine.QueryEngine;
import cn.edu.engine.qvog.engine.dsl.lib.flow.TaintFlowPredicate;
import cn.edu.engine.qvog.engine.language.cxx.CxxQuery;
import cn.edu.engine.qvog.engine.language.cxx.lib.ContainsCxxSystemExit;
import cn.edu.engine.qvog.engine.language.shared.predicate.ContainsFunctionCall;

public class MutexNotReleased extends CxxQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance()
                .execute(MutexNotReleased.class.getSimpleName(), new MutexNotReleased())
                .close();
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                .from("source", new ContainsFunctionCall("pthread_mutex_lock"))
                .from("sink", new ContainsFunctionCall("pthread_mutex_unlock"))
                .where(TaintFlowPredicate.with()
                        .source("source")
                        .sink("sink")
                        .addSysExitAsSink(true)
                        .specialSink(new ContainsFunctionCall("pthread_exit")
                                .or(new ContainsCxxSystemExit()))
                        .as("path").exists())
                .select("source", "sink");
    }
}
