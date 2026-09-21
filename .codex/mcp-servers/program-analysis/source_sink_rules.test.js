"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function idsMatching(lang, content) {
  const hits = [];
  for (const rule of RULES.filter((r) => r.lang === lang)) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(content)) hits.push(rule.id);
  }
  return hits;
}

// --- XXE (CWE-611) true positives ---

test("java: DocumentBuilderFactory.newInstance() is flagged as an XXE sink", () => {
  const src =
    "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();";
  assert.ok(idsMatching("java", src).includes("java.xml.factory_newinstance"));
});

test("java: SAXParserFactory/XMLInputFactory/TransformerFactory are also flagged", () => {
  assert.ok(
    idsMatching("java", "SAXParserFactory.newInstance()").includes(
      "java.xml.factory_newinstance",
    ),
  );
  assert.ok(
    idsMatching("java", "XMLInputFactory.newInstance()").includes(
      "java.xml.factory_newinstance",
    ),
  );
  assert.ok(
    idsMatching("java", "TransformerFactory.newInstance()").includes(
      "java.xml.factory_newinstance",
    ),
  );
});

test("python: stdlib and lxml XML parse calls are flagged as XXE sinks", () => {
  assert.ok(
    idsMatching("py", "xml.etree.ElementTree.parse(f)").includes(
      "py.xml.stdlib_parse",
    ),
  );
  assert.ok(
    idsMatching("py", "tree = ET.fromstring(payload)").includes(
      "py.xml.stdlib_parse",
    ),
  );
  assert.ok(
    idsMatching("py", "xml.dom.minidom.parseString(data)").includes(
      "py.xml.stdlib_parse",
    ),
  );
  assert.ok(
    idsMatching("py", "parser = xml.sax.make_parser()").includes(
      "py.xml.stdlib_parse",
    ),
  );
  assert.ok(
    idsMatching("py", "lxml.etree.parse(untrusted)").includes(
      "py.xml.stdlib_parse",
    ),
  );
});

test("js: an explicit noent: true is flagged as an XXE sink", () => {
  const src = "libxmljs.parseXml(body, { noent: true, dtdload: true })";
  assert.ok(idsMatching("js", src).includes("js.libxml.noent_enabled"));
});

// --- XXE true negatives (deliberately not flagged) ---

test("js: libxmljs with noent left at its safe default is not flagged", () => {
  const src = "libxmljs.parseXml(body, { noent: false })";
  assert.ok(!idsMatching("js", src).includes("js.libxml.noent_enabled"));
});

test("go: encoding/xml has no XXE sink -- it has no DTD/external-entity support", () => {
  const src = "xml.Unmarshal(data, &v)";
  const goCweIds = RULES.filter((r) => r.lang === "go" && r.cwe === "CWE-611");
  assert.equal(goCweIds.length, 0);
  assert.deepEqual(idsMatching("go", src), []);
});

// --- whole-ruleset sanity checks ---

test("every rule id is unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule carries a cwe", () => {
  for (const rule of RULES.filter((r) => r.kind === "sink")) {
    assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe`);
  }
});
