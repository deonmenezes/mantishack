# Mantis benchmark scoreboard

**Overall:** 21 / 104 solved (20.2%). Addressable: 21 / 60 (35.0%).

## Status breakdown

| status | count |
|---|---:|
| solved | 21 |
| no_flag | 36 |
| timeout | 3 |
| build_failed | 15 |
| run_failed | 6 |
| blocked_phantomjs | 23 |

## By difficulty level

| level | solved | total | rate |
|---|---:|---:|---:|
| 1 | 11 | 45 | 24.4% |
| 2 | 10 | 51 | 19.6% |
| 3 | 0 | 8 | 0.0% |

## By vuln class

| tag | solved | no_flag | total | rate |
|---|---:|---:|---:|---:|
| xss | 0 | 0 | 23 | 0.0% |
| default_credentials | 8 | 6 | 18 | 44.4% |
| idor | 7 | 4 | 15 | 46.7% |
| privilege_escalation | 5 | 4 | 14 | 35.7% |
| ssti | 3 | 6 | 13 | 23.1% |
| command_injection | 2 | 5 | 11 | 18.2% |
| business_logic | 3 | 3 | 7 | 42.9% |
| arbitrary_file_upload | 1 | 3 | 6 | 16.7% |
| information_disclosure | 2 | 3 | 6 | 33.3% |
| insecure_deserialization | 1 | 3 | 6 | 16.7% |
| lfi | 2 | 3 | 6 | 33.3% |
| sqli | 1 | 2 | 6 | 16.7% |
| path_traversal | 1 | 2 | 5 | 20.0% |
| cve | 1 | 1 | 4 | 25.0% |
| blind_sqli | 0 | 2 | 3 | 0.0% |
| crypto | 1 | 2 | 3 | 33.3% |
| graphql | 0 | 1 | 3 | 0.0% |
| jwt | 1 | 0 | 3 | 33.3% |
| ssrf | 0 | 3 | 3 | 0.0% |
| xxe | 0 | 2 | 3 | 0.0% |
| brute_force | 1 | 0 | 2 | 50.0% |
| http_method_tamper | 1 | 0 | 1 | 100.0% |
| nosqli | 0 | 0 | 1 | 0.0% |
| race_condition | 0 | 1 | 1 | 0.0% |
| smuggling_desync | 0 | 0 | 1 | 0.0% |
| ssh | 1 | 0 | 1 | 100.0% |

## Solved benchmark durations

p50: **1234s** · p90: **3287s** · max: **6270s** (n=21)

## Where to invest next

- **default_credentials**: 10 unsolved of 18 (44.4% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **ssti**: 10 unsolved of 13 (23.1% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **command_injection**: 9 unsolved of 11 (18.2% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **idor**: 8 unsolved of 15 (46.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **privilege_escalation**: 9 unsolved of 14 (35.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **business_logic**: 4 unsolved of 7 (42.9% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **arbitrary_file_upload**: 5 unsolved of 6 (16.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **information_disclosure**: 4 unsolved of 6 (33.3% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
