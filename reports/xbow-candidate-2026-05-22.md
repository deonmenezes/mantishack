# Mantis benchmark scoreboard

**Overall:** 19 / 104 solved (18.3%). Addressable: 19 / 60 (31.7%).

## Status breakdown

| status | count |
|---|---:|
| solved | 19 |
| no_flag | 40 |
| timeout | 1 |
| build_failed | 15 |
| run_failed | 6 |
| blocked_phantomjs | 23 |

## By difficulty level

| level | solved | total | rate |
|---|---:|---:|---:|
| 1 | 11 | 45 | 24.4% |
| 2 | 8 | 51 | 15.7% |
| 3 | 0 | 8 | 0.0% |

## By vuln class

| tag | solved | no_flag | total | rate |
|---|---:|---:|---:|---:|
| xss | 0 | 0 | 23 | 0.0% |
| default_credentials | 7 | 8 | 18 | 38.9% |
| idor | 7 | 4 | 15 | 46.7% |
| privilege_escalation | 3 | 6 | 14 | 21.4% |
| ssti | 3 | 7 | 13 | 23.1% |
| command_injection | 2 | 5 | 11 | 18.2% |
| business_logic | 2 | 4 | 7 | 28.6% |
| arbitrary_file_upload | 1 | 3 | 6 | 16.7% |
| information_disclosure | 2 | 3 | 6 | 33.3% |
| insecure_deserialization | 1 | 4 | 6 | 16.7% |
| lfi | 2 | 3 | 6 | 33.3% |
| sqli | 1 | 2 | 6 | 16.7% |
| path_traversal | 1 | 2 | 5 | 20.0% |
| cve | 1 | 1 | 4 | 25.0% |
| blind_sqli | 0 | 2 | 3 | 0.0% |
| crypto | 0 | 3 | 3 | 0.0% |
| graphql | 0 | 1 | 3 | 0.0% |
| jwt | 1 | 0 | 3 | 33.3% |
| ssrf | 0 | 3 | 3 | 0.0% |
| xxe | 0 | 2 | 3 | 0.0% |
| brute_force | 0 | 1 | 2 | 0.0% |
| http_method_tamper | 0 | 1 | 1 | 0.0% |
| nosqli | 0 | 0 | 1 | 0.0% |
| race_condition | 0 | 1 | 1 | 0.0% |
| smuggling_desync | 0 | 0 | 1 | 0.0% |
| ssh | 1 | 0 | 1 | 100.0% |

## Solved benchmark durations

p50: **1231s** · p90: **2034s** · max: **3287s** (n=19)

## Where to invest next

- **default_credentials**: 11 unsolved of 18 (38.9% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **ssti**: 10 unsolved of 13 (23.1% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **privilege_escalation**: 11 unsolved of 14 (21.4% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **command_injection**: 9 unsolved of 11 (18.2% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **idor**: 8 unsolved of 15 (46.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **business_logic**: 5 unsolved of 7 (28.6% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **insecure_deserialization**: 5 unsolved of 6 (16.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **arbitrary_file_upload**: 5 unsolved of 6 (16.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
