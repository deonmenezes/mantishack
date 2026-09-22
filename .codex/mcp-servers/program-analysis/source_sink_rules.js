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
    id: "js.fs.read_dynamic_path",
    // fs.readFile/readFileSync/createReadStream called with anything other
    // than a string/template literal as the first argument -- e.g.
    // fs.readFile(path.join(base, req.params.file)) or fs.readFile(userPath).
    // A literal path.join("a", "b") call still starts with an identifier, not
    // a quote, so it's flagged too; that's intentional recall over precision.
    pattern:
      /\bfs\.(?:readFile|readFileSync|createReadStream)\s*\((?!\s*['"`])/g,
    cwe: "CWE-22",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.fs.write_dynamic_path",
    pattern:
      /\bfs\.(?:writeFile|writeFileSync|createWriteStream|unlink|unlinkSync)\s*\((?!\s*['"`])/g,
    cwe: "CWE-22",
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
    id: "py.flask.send_file_dynamic",
    // Flask's send_file(path) serves whatever path it's given; a path built
    // from request data without validation is the classic Flask path-
    // traversal vector (CVE-2018-16487-style bugs). Literal paths ("static/x")
    // don't match.
    pattern: /\bsend_file\s*\((?!\s*['"])/g,
    cwe: "CWE-22",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.flask.send_from_directory_dynamic",
    // send_from_directory(directory, filename) is traversal-safe against its
    // *directory* arg (Flask normalizes/rejects ../ there) but not always
    // against how callers build `filename` -- flag when filename itself
    // isn't a literal.
    pattern: /\bsend_from_directory\s*\([^,)]*,(?!\s*['"])/g,
    cwe: "CWE-22",
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
    id: "go.os.open_dynamic_path",
    pattern: /\bos\.(?:Open|OpenFile|ReadFile|Create)\s*\((?!\s*["`])/g,
    cwe: "CWE-22",
  },
  {
    lang: "go",
    kind: "sink",
    id: "go.http.servefile_dynamic",
    // http.ServeFile(w, r, name) -- the traversal-relevant arg is the third
    // (name); w and r are request plumbing, not the path.
    pattern: /\bhttp\.ServeFile\s*\([^,)]*,[^,)]*,(?!\s*["`])/g,
    cwe: "CWE-22",
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
  {
    lang: "java",
    kind: "sink",
    id: "java.fs.file_dynamic_path",
    pattern: /\bnew\s+File(?:InputStream|OutputStream)?\s*\((?!\s*")/g,
    cwe: "CWE-22",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.nio.paths_get_dynamic",
    pattern: /\bPaths\.get\s*\((?!\s*")/g,
    cwe: "CWE-22",
  },
];

module.exports = { RULES };
