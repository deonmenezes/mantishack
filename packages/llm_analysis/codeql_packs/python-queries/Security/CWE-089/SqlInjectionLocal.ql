/**
 * @name IRIS LocalFlowSource: SQL injection from local input
 * @description Reuses the stdlib SqlInjection sink and sanitiser
 *              models with MANTISHACK's `LocalFlowSource` to catch
 *              CLI / env / stdin-driven SQL injection that the
 *              stdlib RemoteFlowSource-based query misses.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id mantishack/iris/python/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.SqlInjectionCustomizations
import Mantishack.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof SqlInjection::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ flows to a SQL query.",
  source.getNode(), source.getNode().toString()
