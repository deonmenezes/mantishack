"use strict";

/**
 * Heuristic attacker-controlled-source / dangerous-sink tagger.
 *
 * This is intentionally NOT a dataflow/taint engine -- it is a fast,
 * dependency-free proxy that surfaces candidate source and sink lines for a
 * human or the Validate-stage agent to actually trace and connect (FR-3.1/
 * FR-3.2's recall goal). It never claims reachability by itself; pair it
 * with smt_check_reachability once a concrete path condition is formed.
 */
const RULES = [
  // JavaScript / TypeScript
  {
    lang: "js",
    kind: "source",
    id: "js.http.query",
    pattern: /\breq\.(query|body|params|headers|cookies)\b/g,
  },
  {
    lang: "js",
    kind: "source",
    id: "js.process.argv",
    pattern: /\bprocess\.argv\b/g,
  },
  {
    lang: "js",
    kind: "source",
    id: "js.browser.location",
    pattern:
      /\b(location|window\.location|document\.location)\.(hash|search|href)\b/g,
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.eval",
    pattern: /\beval\s*\(/g,
    cwe: "CWE-95",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.new_function",
    pattern: /\bnew\s+Function\s*\(/g,
    cwe: "CWE-95",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.child_process.exec",
    pattern: /\b(child_process\.)?(exec|execSync)\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.dom.innerhtml",
    pattern: /\b(innerHTML|outerHTML)\s*=/g,
    cwe: "CWE-79",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.react.dangerously_set_inner_html",
    pattern: /dangerouslySetInnerHTML/g,
    cwe: "CWE-79",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.document.write",
    pattern: /\bdocument\.write\s*\(/g,
    cwe: "CWE-79",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.deserialize",
    pattern: /\b(node-serialize|serialize\.unserialize)\s*\(/g,
    cwe: "CWE-502",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.sql.template_literal",
    // `.query(`...${x}...`)` / `.execute(`...${x}...`)` -- attacker value
    // interpolated straight into the SQL text instead of passed as a bound
    // parameter.
    pattern: /\.(query|execute|raw)\s*\(\s*`[^`]*\$\{/g,
    cwe: "CWE-89",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.sql.string_concat",
    // `.query("... " + x)` -- SQL text built by string concatenation.
    pattern: /\.(query|execute|raw)\s*\(\s*(['"])(?:(?!\2).)*\2\s*\+/g,
    cwe: "CWE-89",
  },

  // Python
  {
    lang: "py",
    kind: "source",
    id: "py.flask.request",
    pattern: /\brequest\.(args|form|values|cookies|headers|json)\b/g,
  },
  {
    lang: "py",
    kind: "source",
    id: "py.django.request",
    pattern: /\brequest\.(GET|POST)\b/g,
  },
  { lang: "py", kind: "source", id: "py.sys.argv", pattern: /\bsys\.argv\b/g },
  {
    lang: "py",
    kind: "sink",
    id: "py.eval_exec",
    pattern: /\b(eval|exec)\s*\(/g,
    cwe: "CWE-95",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.os.system",
    pattern: /\bos\.system\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.subprocess.shell_true",
    pattern: /subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/g,
    cwe: "CWE-78",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.pickle.loads",
    pattern: /\bpickle\.loads?\s*\(/g,
    cwe: "CWE-502",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.yaml.load_unsafe",
    pattern: /\byaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)/g,
    cwe: "CWE-502",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.sql.execute_fstring",
    // cursor.execute(f"... {x} ...") -- attacker value interpolated into SQL
    // text instead of passed via the execute(sql, params) bind-parameter form.
    pattern: /\.execute\s*\(\s*f['"]/g,
    cwe: "CWE-89",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.sql.execute_percent_or_format",
    // cursor.execute("... %s" % x) / cursor.execute("...{}".format(x)) -- same
    // string-built-SQL shape as the f-string case above.
    pattern: /\.execute\s*\(\s*(['"])(?:(?!\1).)*\1\s*(%|\.format\s*\()/g,
    cwe: "CWE-89",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.sql.execute_concat",
    // cursor.execute("... " + x) -- SQL text built by string concatenation.
    pattern: /\.execute\s*\(\s*(['"])(?:(?!\1).)*\1\s*\+/g,
    cwe: "CWE-89",
  },

  // Go
  {
    lang: "go",
    kind: "source",
    id: "go.http.request",
    pattern: /\br\.(URL\.Query\(\)|FormValue|PostFormValue)\b/g,
  },
  { lang: "go", kind: "source", id: "go.os.args", pattern: /\bos\.Args\b/g },
  {
    lang: "go",
    kind: "sink",
    id: "go.exec.command",
    pattern: /\bexec\.Command\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "go",
    kind: "sink",
    id: "go.template.html",
    pattern: /\btemplate\.HTML\s*\(/g,
    cwe: "CWE-79",
  },
  {
    lang: "go",
    kind: "sink",
    id: "go.sql.sprintf",
    // db.Query(fmt.Sprintf("... %s ...", x)) -- SQL text built with Sprintf
    // instead of the driver's `?`/`$1` bind-parameter placeholders.
    pattern:
      /\.(Query|QueryRow|Exec)(Context)?\s*\(\s*(\w+(?:\.\w+)*(?:\(\))?\s*,\s*)?fmt\.Sprintf\s*\(/g,
    cwe: "CWE-89",
  },
  {
    lang: "go",
    kind: "sink",
    id: "go.sql.string_concat",
    // db.Query("... " + x) -- SQL text built by string concatenation.
    pattern:
      /\.(Query|QueryRow|Exec)(Context)?\s*\(\s*(\w+(?:\.\w+)*(?:\(\))?\s*,\s*)?"[^"]*"\s*\+/g,
    cwe: "CWE-89",
  },

  // Java
  {
    lang: "java",
    kind: "source",
    id: "java.servlet.request",
    pattern: /\brequest\.get(Parameter|Header|QueryString)\s*\(/g,
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.runtime.exec",
    pattern: /\bRuntime\.getRuntime\(\)\.exec\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.processbuilder",
    pattern: /\bnew\s+ProcessBuilder\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.objectinputstream",
    pattern: /\bnew\s+ObjectInputStream\s*\(/g,
    cwe: "CWE-502",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.statement.execute",
    pattern: /\bstatement\.execute(Query|Update)?\s*\(/gi,
    cwe: "CWE-89",
  },
];

module.exports = { RULES };
