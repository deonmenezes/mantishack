# Mantis benchmark scoreboard

**Overall:** 11 / 104 solved (10.6%). Addressable: 11 / 60 (18.3%).

## Status breakdown

| status | count |
|---|---:|
| solved | 11 |
| no_flag | 49 |
| build_failed | 15 |
| run_failed | 6 |
| blocked_phantomjs | 23 |

## By difficulty level

| level | solved | total | rate |
|---|---:|---:|---:|
| 1 | 5 | 45 | 11.1% |
| 2 | 6 | 51 | 11.8% |
| 3 | 0 | 8 | 0.0% |

## By vuln class

| tag | solved | no_flag | total | rate |
|---|---:|---:|---:|---:|
| xss | 0 | 0 | 23 | 0.0% |
| default_credentials | 6 | 10 | 18 | 33.3% |
| idor | 6 | 7 | 15 | 40.0% |
| privilege_escalation | 1 | 8 | 14 | 7.1% |
| ssti | 2 | 8 | 13 | 15.4% |
| command_injection | 0 | 7 | 11 | 0.0% |
| business_logic | 0 | 6 | 7 | 0.0% |
| arbitrary_file_upload | 1 | 3 | 6 | 16.7% |
| information_disclosure | 1 | 4 | 6 | 16.7% |
| insecure_deserialization | 1 | 4 | 6 | 16.7% |
| lfi | 2 | 3 | 6 | 33.3% |
| sqli | 1 | 2 | 6 | 16.7% |
| path_traversal | 1 | 2 | 5 | 20.0% |
| cve | 0 | 2 | 4 | 0.0% |
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
| ssh | 0 | 1 | 1 | 0.0% |

## Solved benchmark durations

p50: **1218s** · p90: **1234s** · max: **1978s** (n=11)

## Where to invest next

- **default_credentials**: 12 unsolved of 18 (33.3% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **privilege_escalation**: 13 unsolved of 14 (7.1% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **ssti**: 11 unsolved of 13 (15.4% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **idor**: 9 unsolved of 15 (40.0% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **command_injection**: 11 unsolved of 11 (0.0% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **business_logic**: 7 unsolved of 7 (0.0% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **information_disclosure**: 5 unsolved of 6 (16.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
- **insecure_deserialization**: 5 unsolved of 6 (16.7% solve rate). Build dedicated playbook + verify nuclei templates cover the class.
