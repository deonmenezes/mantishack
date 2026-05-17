**Doc-vs-Behavior Differential.** Ingest OpenAPI 3 / GraphQL SDL / Postman v2.1 with `mantis_ingest_schema_doc` (content-hashed, idempotent), confirm coverage with `mantis_query_schema_contracts`, run per auth profile via `mantis_run_doc_delta({ target_domain, base_url, auth_profile, run_id })`, read with `mantis_read_doc_delta_results({ target_domain, summary_only: true })`. Divergence classes: `security`, `info_leak_potential`, `doc_or_infra`.

Web hunters also see the schema corpus through `schema_slice` in their brief once it's seeded.
