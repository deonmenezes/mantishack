/**
 * @name IRIS LocalFlowSource: command injection from local input
 * @description Reuses the stdlib Java CommandInjection sink and
 *              sanitiser models with MANTISHACK's `LocalFlowSource` so
 *              args[]- / System.getenv- / stdin-driven flows that the
 *              stock `ActiveThreatModelSource` configuration excludes
 *              are caught.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id mantishack/iris/java/command-injection-local
 * @tags security
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.CommandLineQuery
import Mantishack.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof CommandInjectionSink }

  predicate isBarrier(DataFlow::Node n) { n instanceof CommandInjectionSanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a command-execution sink."
