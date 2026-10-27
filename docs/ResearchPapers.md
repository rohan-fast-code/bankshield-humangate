# Latest Research Papers On AI Reverse Engineering And What Banking Can Do About It
Research read on 27 October 2026. Focus: AI assisted reverse engineering, code protection, secret leakage in mobile apps, and agent tool security, all mapped to banking only defence. Paper titles below are paraphrased without punctuation changes that matter for search. Use the arXiv identifier to find the exact paper.

## Paper 1. Constraint Guided Multi Agent Decompilation For Executable Binary Recovery
Date: revised 1 May 2026. Identifier: arXiv 2604.23940.
Core finding: A multi agent framework turns decompiler output into code that can run again. It checks syntax, then compilation, then behaviour with LLM generated tests, and it refines code when a check fails. On 1641 real binaries it reached 84 to 97 percent reexecutability, an improvement of 28 to 89 percentage points over baseline decompilers, at an average cost of 0.03 to 0.05 dollars per binary, with more than 90 percent reaching correctness within 2 iterations.
Banking lesson: Rebuilding an app is no longer a weeks long expert job. It is cheap, iterative, and test driven. A bank cannot rely on the idea that its binary is too hard to read.

## Paper 2. Binary Decompilation LLM With Feedback Driven Multi Turn Refinement
Date: first version 15 June 2026, revised 3 October 2026. Identifier: arXiv 2606.16162.
Core finding: The AutoDecompiler family learns from compiler errors, execution failures, and failed tests across multiple turns. It beats single turn decompilation at the same model size, with clear gains in behavioural reexecutability. Feedback, not just a bigger model, is the improvement.
Banking lesson: An attacker agent will not stop at one decompiled output. It will compile, run, fail, and fix. Defence must therefore break the feedback loop, for example by making recovered code fail against the real server, not only look confusing on first read.

## Paper 3. Automatically Attacking Software Reverse Engineering AI Agents
Date: submitted 28 May 2026. Identifier: arXiv 2605.30667.
Core finding: LLM powered disassembly can be deceived. Using a genetic prompt generation method adapted from AutoDAN, the authors hide instructions inside extraneous string assignments in a binary. The binary still works normally, but the LLM misinterprets the decompiled output. This can bypass automated detection pipelines that rely on LLM analysis.
Banking lesson: This is a double edged finding. It proves LLM analysis is fragile to injected text, which suggests decoy strings could mislead a cloning agent. It also proves you must not trust an LLM alone to judge whether code is safe. For banking, decoys are useful only as a secondary layer, never as a replacement for server side checks, and they must never contain real customer data or real logic.

## Paper 4. Acoda Adversarial Code Obfuscation For Defending Against LLM Based Analysis
Date: submitted 10 June 2026. Identifier: arXiv 2606.11755.
Core finding: Acoda is a genetic algorithm based adversarial obfuscation framework. It uses 8 semantics preserving obfuscation methods, designed around LLM safety alignment and token based processing, and it optimises the combination over iterations. On 7 leading LLMs it induced refusal or misinterpretation with an attack success rate up to 70 percent, with strong transfer across models and minimal runtime overhead, while the original code behaviour stayed unchanged.
Banking lesson: This is the most directly useful defensive paper for code on the phone. It shows you can make LLM analysis fail without breaking the app. For banking, apply this style of obfuscation only to non critical display and flow code, and keep money logic off the phone entirely. Obfuscation buys time, it does not replace server side authority.

## Paper 5. PUSHAN Trace Free Deobfuscation Of Virtualization Obfuscated Binaries
Date: submitted 18 March 2026. Identifier: arXiv 2603.18355.
Core finding: Virtualization obfuscation, often presented as the strongest protection, can be undone without execution traces. PUSHAN uses VPC sensitive constraint free symbolic emulation to recover the complete control flow graph of a virtualized function, then decompiles it to readable C pseudocode. It was tested on more than 1000 binaries, including targets protected by Tigress, VMProtect, and Themida, and its output then enabled LLM assisted simplification and reuse.
Banking lesson: Do not sell virtualization as a final answer. It raises cost, but a determined attacker with modern deobfuscation plus an LLM can still recover logic. Rotate the virtual machine layout often, and never put a secret or a fraud rule inside virtualized phone code that the server could decide instead.

## Paper 6. Secrets Unlocked Evaluating LLMs For Secrets Detection In Android Apps, Known As SecretLoc
Date: submitted 21 October 2025, ISSTA version October 2026. Identifier: arXiv 2510.18601 in the search listing.
Core finding: SecretLoc uses LLM contextual and structural cues, not only regex patterns, to find hardcoded secrets in Android apps. It found 4828 secrets missed by regex, static, and machine learning methods, including new types such as OpenAI keys, GitHub tokens, RSA private keys, and JWT tokens. Across 5000 newly crawled Play Store apps, it found secrets in 2124 apps, which is 42.5 percent.
Banking lesson: This is the banking emergency in one number. If an LLM can find secrets that old scanners miss, an attacker LLM will find a hardcoded bank key the same way. Banking apps must have zero hardcoded secrets, short lived device bound tokens, server side keys in a hardware security module, and a pre release LLM secret scan as a gate, not an afterthought.

## Paper 7. ToFu Tool Aware Fuzzing For MCP Servers
Date: published 9 October 2026. Identifier: arXiv 2610.13651.
Core finding: ToFu fuzzed 273 open source MCP servers containing 3405 tools. It found verified bugs in 343 tools across 118 servers. The root cause is tools that do not enforce their own documented input rules, so an agent passing model generated arguments straight through can be steered into unsafe behaviour. The authors argue that LLM generated arguments must be treated as untrusted input.
Banking lesson: Every MCP tool your bank agent uses is a potential attack surface. Fuzz your own agent tools before deployment, validate every argument on the server side, scope permissions to the minimum, and log every call. AgentGuard must be a server side gateway, not a prompt instruction.

## Paper 8. My Credentials Please Detecting Filesystem Capability Laundering In MCP Servers At Scale
Date: submitted 15 October 2026. Identifier: arXiv 2610.22301.
Core finding: Client side approval of a tool call does not restrict the server process to the declared operation. It grants broad host filesystem permissions. Attacker steered arguments can therefore make a tool read files outside its declared contract, a class the authors call filesystem capability laundering. Across 21097 MCP servers from nine registries, 787 of 4806 triaged servers, which is 16.4 percent, showed filesystem capability despite non filesystem classifications. Dynamic validation confirmed 150 vulnerable instances, and coordinated disclosure produced 13 advisories, including two CVEs in Anthropic Git MCP Server.
Banking lesson: This kills the idea that asking a human to approve a tool call is enough. Approval approves the name of the call, not the files it can actually reach. For finance code, run each agent tool in a sandbox that mounts only what it needs, resolve canonical paths against a declared root, and keep credentials outside the account the agent server runs under.

## Paper 9. MCPShield A Formal Security Framework For MCP Based AI Agents
Date: submitted 7 April 2026. Identifier: arXiv 2604.05969.
Core finding: The authors analyse more than 177000 MCP tools and build a taxonomy of 7 threat categories and 23 attack vectors across four attack surfaces. They evaluate 12 existing defences and find no single defence covers more than 34 percent of the threat landscape. Their integrated architecture, combining capability based access control, cryptographic tool attestation, information flow tracking, and runtime policy enforcement, reaches a theoretical coverage of 91 percent.
Banking lesson: This is the academic justification for a layered AgentGuard. Do not buy or build one control and call the agent safe. Combine tool attestation, capability limits, flow tracking, and runtime policy, and measure coverage against a taxonomy, not against one demo attack.

## Paper 10. Fighting Fire With Venom Adversarial Defense Against Unauthorized Web Crawling
Venue: USENIX Security 2025 talk.
Core finding: Venom fingerprints crawlers using headers, behaviour patterns, and known infrastructure, then serves different or misleading content to identified crawlers through an inline proxy. LLMs trained on intentionally poisoned content show degraded performance, which reshapes the cost benefit equation for unscrupulous collection. Blocking alone leaves the value of stolen data unchanged. Poisoning makes stolen data low quality.
Banking lesson: Translate this to banking APIs with care. Fingerprint systematic probing sessions, not real users. For a session that looks like machine speed API coverage, throttle it, challenge it, or serve a decoy response set that contains no real pricing, fraud, or account logic. Never serve decoys to a verified real user, and never let a decoy affect a real transaction.

## Paper 11. An Embarrassingly Simple Detector For Model Extraction Attacks In LLM API Traffic
Date: posted 4 June 2026. Identifier: arXiv 2606.05725.
Core finding: Instead of flagging single suspicious queries, test whether a window of recent traffic has drifted from historical benign traffic, using a distribution test over query embeddings calibrated on benign traffic only. As reported, this reached 0.3 percent false positives and 100 percent detection on pure attacker streams in the reported test.
Banking lesson: This is the detection model banking APIs need. A reverse engineering agent does not look suspicious in one call. It looks suspicious across a window: high API coverage, systematic order, machine timing, and repeated parameter probing. Score the window, not the call, and act before the full API surface is mapped.

## Synthesis: What Can Be Done, In Priority Order
1. Move money logic to the server. Papers 1 and 2 prove recovered phone code can be made runnable and iteratively fixed. If the logic is not in the phone code, recovery gives an attacker screens only.
2. Remove secrets from the phone and from agent context. Paper 6 proves LLM secret discovery beats old scanners. Use vaults, hardware security modules, short lived device bound tokens, and tokenization.
3. Use adversarial obfuscation as a delay layer, not a vault. Paper 4 shows up to 70 percent LLM refusal or misinterpretation. Paper 5 shows virtualization alone can be undone. Rotate code shape, and combine obfuscation with server side authority.
4. Build AgentGuard as a server side gateway, not a prompt. Papers 7, 8, and 9 together prove approval is not a boundary, tool arguments are untrusted, and only a layered architecture covers most threats. Enforce path roots, sandboxing, tool attestation, capability limits, and full audit logging in code the model cannot talk its way past.
5. Detect probing as a window, and degrade stolen data. Papers 10 and 11 give the pattern: fingerprint systematic behaviour, test traffic windows against benign baselines, throttle or decoy suspected reverse sessions, and trace clones by watermark and behaviour fingerprint.
6. Test on your own demo, with numbers. A bank or a student project should measure: time to recover fee logic from the vulnerable app versus the shielded app, secret detection rate before release, number of MCP tool abuse attempts blocked, and false positive rate for real users. Without those numbers, a defence claim is only a slide.

## Honest Limits From The Papers
Most of these papers are preprints from 2025 to 2026, not yet all peer reviewed, and their headline numbers are author reported results on their own benchmarks. Results will differ on a real banking app, on a different model, and under a different attacker budget. Acoda and decoy ideas also carry a risk: if decoys leak into real user flows, or if obfuscation breaks accessibility or performance, the defence harms the bank it is meant to protect. Treat every paper as a direction to reproduce in your own lab, on your own code, with your own permission, never as a guarantee.
