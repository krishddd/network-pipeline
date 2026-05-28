# **Autonomous Adversary Emulation and the Evolution of Red Team Automation: A Deep Dive into the Decepticon Framework and the MITRE ATT\&CK Ecosystem**

## **The Paradigmatic Shift in Offensive Cybersecurity Operations**

The cybersecurity industry is undergoing a structural and philosophical realignment, transitioning away from deterministic, point-in-time security assessments toward continuous, autonomous adversary emulation. Historically, securing digital infrastructure relied on a spectrum of testing methodologies ranging from passive vulnerability scanning to manual penetration testing and human-led red team exercises. However, the advent of generative artificial intelligence and autonomous agentic frameworks has profoundly disrupted these paradigms, enabling machine-speed execution of complex, multi-stage attack chains.1 Within this rapidly evolving landscape, the distinction between rudimentary automation—often characterized by disparate script execution and noisy vulnerability sweeping—and professional-grade adversary emulation has become paramount.

Traditional red teaming borrows its terminology and core philosophy from Cold War-era military wargaming, where an independent opposing force (OPFOR) simulates realistic adversarial behavior to reduce institutional groupthink and rigorously test the assumptions of network defenders.4 It is defined not merely by the technical capability to exploit vulnerabilities, but by strict adherence to operational discipline, predefined objectives, and exhaustive pre-engagement planning. A critical gap has emerged in the domain of automated offensive security tools: many existing solutions operate as sophisticated vulnerability scanners or digital "script kiddies," firing one-shot exploits without maintaining operational security (OPSEC), stateful persistence, or contextual awareness.5

To bridge this operational gap, specialized automation frameworks like the Decepticon agent have been engineered. Operating under the philosophy that true red teaming is an operations-driven discipline, Decepticon fundamentally reimagines autonomous exploitation. Before transmitting a single network packet or initiating a reconnaissance scan, it systematically generates comprehensive engagement packages—including Rules of Engagement (RoE), Concept of Operations (ConOps), Deconfliction Plans, and Operations Plans (OPPLAN) mapped directly to the MITRE ATT\&CK framework.5 By orchestrating multiple specialized AI sub-agents across isolated networks, deploying interactive terminal multiplexer (tmux) sessions, and closing the security feedback loop with an "Offensive Vaccine" mechanism, this framework establishes a new baseline for continuous, threat-informed defense.5 This report explores the technological architecture, the theoretical underpinnings of agentic state management, and the operational doctrine that separates professional autonomous red teaming from legacy automated testing.

## **Taxonomic Distinctions in Security Validation**

To comprehend the architectural necessity of advanced autonomous frameworks, one must first delineate the operational boundaries and fundamental limitations of existing cybersecurity testing methodologies. The transition to AI-driven attack surfaces requires a corresponding evolution in how security validation is defined and executed.

### **Deterministic Scanning and Breach and Attack Simulation**

Vulnerability scanning is a passive, automated process that relies on enumerating known security weaknesses against a static database of Common Vulnerabilities and Exposures (CVEs).1 While highly scalable and essential for maintaining baseline infrastructure hygiene—such as identifying unpatched software versions, open ports, or misconfigured services—it is definitionally limited to historical data.1 Scanners are inherently incapable of identifying novel attack paths or executing the logical leaps required to chain disparate, low-severity misconfigurations into a full system compromise. Furthermore, they are entirely blind to the vulnerabilities unique to generative AI systems. Issues such as prompt injection, Reinforcement Learning from Human Feedback (RLHF) exploitation, persona attacks, and Retrieval-Augmented Generation (RAG) poisoning do not have standard CVE entries and cannot be detected via port scanning.1

Breach and Attack Simulation (BAS) platforms represent an evolutionary step in automation, providing the continuous simulation of tactics, techniques, and procedures (TTPs) to validate defensive controls.1 However, traditional BAS is predominantly optimized for legacy infrastructure and deterministic environments. These tools typically run fixed attack playbooks. They struggle to account for the probabilistic nature of modern systems and lack the goal-directed autonomy required to pivot dynamically when an initial attack vector fails or encounters a novel defensive countermeasure.1

### **The Limitations of Manual Penetration Testing**

Penetration testing is an active, human-led assessment designed to exploit vulnerabilities within a specific scope and timeframe, serving essentially as a point-in-time validation exercise.1 While penetration tests often leverage automated tools for reconnaissance, the core exploitation logic relies on human intuition. However, traditional security testing was designed for deterministic systems, which presents a critical structural failure when applied to AI infrastructure.1

Large Language Models (LLMs) and agentic systems are probabilistic; the same input prompt may produce different outputs across sequential runs. For instance, a model that refuses a harmful jailbreak request 80% of the time will likely pass a point-in-time manual penetration test if the human tester happens to run their query during that 80% window of compliance.1 A single-pass penetration test misses the vulnerability in 70% to 80% of attempts.1 Statistical sampling across hundreds of algorithmic attack variations is the only mathematically sound way to measure actual risk against a probabilistic model, a task that exceeds manual human capacity but is ideally suited for autonomous agents.1

### **Goal-Directed Adversary Emulation**

Red teaming, conversely, is not inherently focused on discovering every vulnerability; rather, it is a goal-directed emulation of an adversary.4 The primary objective is to holistically test the organization's detection, response, and resilience capabilities across the entire Cyber Kill Chain.4 Red teams focus on the operational "story" and the tangible impact of an attack, utilizing stealth, payload obfuscation, process injection, and fileless attack methods to bypass endpoint protections.4

The integration of agentic Large Language Models introduces a new operational paradigm: Goal-Directed Autonomy. Autonomous red team agents operate with explicit objectives, such as privilege escalation, lateral movement, or data exfiltration, rather than executing fixed scripts.10 These agents independently select tactics, sequence their actions, and evaluate environmental feedback in real-time, allowing them to explore viable attack paths under conditions of deep uncertainty.10 Recent research from the University of Illinois Urbana-Champaign demonstrated that AI agents successfully exploited 87% of real-world CVEs when granted access to tool-call capabilities, highlighting the unprecedented speed and efficiency gains that emerge from horizontally scalable autonomous operations.1

| Methodology | Operational Paradigm | Execution Model | Limitations in Modern Environments |
| :---- | :---- | :---- | :---- |
| **Vulnerability Scanning** | Passive Enumeration | Deterministic / Database-driven | Blind to zero-days, logical flaws, and probabilistic AI vulnerabilities (e.g., prompt injection, jailbreaks).1 |
| **Penetration Testing** | Point-in-Time Exploitation | Manual / Tool-Assisted | Ineffective for continuous validation; statistically fails against probabilistic LLM targets.1 |
| **Breach & Attack Sim (BAS)** | Continuous Validation | Scripted TTP Playbooks | Lacks dynamic pivoting; often blocked by basic heuristic defenses; relies on static infrastructure techniques.1 |
| **Autonomous Red Teaming** | Goal-Directed Emulation | Stateful Multi-Agent Autonomy | Requires complex operational guardrails (RoE/Deconfliction) to prevent catastrophic production impact and kinetic friction.5 |

## **Stateful versus Stateless Architectures in Autonomous Security**

A critical determinant of an autonomous red team agent's efficacy is its architectural capability to maintain context over prolonged operational horizons. Artificial intelligence systems deployed for offensive security are rapidly evolving from simple, stateless prompt-response models to stateful, autonomous agents capable of reasoning, complex planning, and performing multi-step tasks across extended temporal boundaries.11

### **The Layered Attack Surface Model (LASM)**

Agentic AI systems face security challenges and operational complexities that stateless language models do not. To categorize these complexities, the Layered Attack Surface Model (LASM) introduces a seven-layer framework mapping threats to distinct architectural components: Foundation, Cognitive, Memory, Tool Execution, Multi-Agent Coordination, Ecosystem, and Governance.12 The Governance layer, analogous to a network management plane, spans the entire stack to provide accountability and observability.12

Stateless AI agents process each request in a vacuum. They are fast, forgetful, and highly scalable because any server can handle any request.13 However, their knowledge is restricted to static training data, and any required historical context must be continually resent with every prompt, leading to severe token limit hits, prompt overflow, and linearly growing token economics.14 This renders stateless agents practically useless for complex network intrusions, which require maintaining the state of multiple interactive shells, tracking the status of enumerated subnets, and remembering which credentials failed during an Active Directory lateral movement attempt.

### **Temporality and Stateful Agent Memory**

Stateful AI agents solve the memory problem by persistently storing context externally, saving tokens and enabling conversational assistants and multi-step workflows.13 However, stateful architecture introduces unique failure modes, including state corruption, stale reads, and race conditions.14

The temporal dimension of attacks further underscores the necessity of statefulness. Attack temporality can be classified into four distinct classes: Instantaneous (T1), Session-Persistent (T2), Cross-Session Cumulative (T3), and Sub-Session-Stack/Non-Session-Bounded (T4).12 The most dangerous emerging threats—such as covert agent collusion, long-term memory poisoning, and supply-chain compromises in the Model Context Protocol (MCP)—concentrate at the intersection of high-layer attacks (LASM layers 5–7) and slow-burn temporality (T3–T4).12 An autonomous red team framework must be structurally designed to operate in this high-layer, slow-burn zone, acting as a persistent, adaptive adversary that maintains operational memory across sessions and system restarts.10

| Architectural Aspect | Stateful Autonomous Agents | Stateless Models / Basic Scanners |
| :---- | :---- | :---- |
| **Operational Memory** | Persistently stores context; tracks multi-step kill chains over weeks. | Forgetful; context must be fully regenerated per request. |
| **Token Economics** | Highly efficient; context is stored externally and retrieved selectively. | Inefficient; full history resent each time, causing linear cost growth and prompt overflow.14 |
| **Scalability Mechanics** | Requires sharded stores or sticky sessions; complex state management. | Easy horizontal scaling; simple API endpoints.14 |
| **Failure Modes** | State corruption, stale reads across multi-agent environments.14 | Context window limitations, hallucination loops.14 |
| **Red Team Viability** | Required for deep lateral movement and persistent Command & Control (C2). | Limited to single-shot exploits and basic reconnaissance. |

## **The Discipline of Emulation: Pre-Engagement Documentation Standards**

What definitively separates professional autonomous agents from rudimentary hacking scripts is the stringent enforcement of rigorous pre-engagement protocols. In a live enterprise production environment, an unconstrained AI agent attempting mass service enumeration, brute-force credential stuffing, or destructive exploitation could easily trigger an automated escalatory spiral.

If an organization utilizes an Autonomous Blue Team (ABT) for active defense, the ABT might detect an anomaly and automatically revoke administrator credentials.2 An undisciplined AI red team, observing this revocation, might logically conclude that it needs to re-establish a foothold and proceed with highly aggressive and noisy exploitation techniques.2 This scenario results in a chaotic feedback loop of "kinetic friction" where two AI agents engage in a rapid-fire conflict over a misinterpreted signal, ultimately locking out legitimate users and halting business operations.2

To prevent collateral damage, fratricide, and uncontrolled escalation, military-grade red teaming enforces strict documentation standards. The Decepticon framework automates this entire lifecycle through its dedicated planning sub-agent, establishing rules before a single tool is invoked.6

### **Rules of Engagement (RoE)**

The Rules of Engagement (RoE) dictate the authorized scope of the operation, explicitly defining what is permitted and what is strictly prohibited.5 The concept of RoE is deeply rooted in military doctrine, serving to codify the inherent right of self-defense and providing guidelines for the application of force to accomplish a mission without violating political or legal boundaries.16

In highly sensitive operational environments—such as healthcare or critical infrastructure, where uninterrupted network stability is literally a matter of life and safety—the RoE acts as a non-negotiable safety perimeter.8 It ensures non-destructive actions, prohibits interference with direct patient care systems, and establishes clear, explicit out-of-scope target lists.8 For an autonomous agent, the RoE parameters are translated directly into system-level constraints. These parameters dictate which IP subnets can be routed, which target ranges are valid, what escalation contacts are required, and establish hard exclusions for fragile legacy systems that might crash under the load of a network scan.5

### **Concept of Operations (ConOps)**

Derived directly from military operational planning, the Concept of Operations outlines the overarching strategy and narrative of the engagement. A ConOps document defines the specific threat actor profile being emulated, such as a nation-state Advanced Persistent Threat (APT) targeting intellectual property, or a financially motivated ransomware affiliate.4

By defining the adversary, the ConOps implicitly dictates the methodology. It defines the specific style of command-and-control (C2) communication, the persistence mechanisms to be utilized, and the indicators of compromise (IOCs) the agent is permitted to generate on the network.4 This is a crucial distinction: by establishing a coherent threat profile, the ConOps ensures that the telemetry generated during the attack accurately tests the Security Operations Center's (SOC) ability to correlate realistic adversarial patterns. Without a ConOps, the autonomous agent would simply throw a disorganized barrage of exploits at the wall, generating noise rather than actionable intelligence.

### **Deconfliction Protocols and SOC Coordination**

Perhaps the most critical component for executing live-environment automated testing is the Deconfliction Plan. During an unannounced (or partially announced) engagement, the defending SOC will inevitably detect anomalous behavior. The blue team must rapidly determine whether the observed activity originates from a genuine malicious threat actor or the authorized autonomous red team.4

An automated Deconfliction Plan provides the SOC with specific operational parameters: source IP addresses, operational time windows, and, crucially, shared cryptographic codes or unique digital signatures.5 By integrating these pre-arranged markers, if the SOC intercepts an attack payload or detects a beaconing C2 channel, they can cross-reference the shared code to confirm it belongs to the red team operation.5 This allows the SOC to accurately log their "time-to-detect" metrics while simultaneously issuing a "stop card" or de-escalating their incident response (IR) procedures, preventing unnecessary and costly full-scale IR deployments for a simulated event.8

### **The Operations Plan (OPPLAN)**

The culmination of the pre-engagement documentation phase is the OPPLAN, which translates the high-level ConOps into a highly granular, step-by-step tactical mission plan.5 In military targeting, this mirrors the Joint Integrated Prioritized Target List (JIPTL) and the Air Tasking Order (ATO) cycles, where targets are nominated based on desired effects, ROE constraints, and available weapon systems.19

In the Decepticon architecture, the OPPLAN contains clearly defined objectives, structured linearly across the condensed phases of the Cyber Kill Chain (e.g., Initial Access, Execution, Privilege Escalation, Lateral Movement, Data Exfiltration).5 The autonomous agent treats this document not as a loose suggestion, but as an immutable state machine, requiring the successful completion and validation of prerequisite objectives before progressing deeper into the network.

## **MITRE ATT\&CK Mapping in Specialized Automation Frameworks**

A defining characteristic of modern red team documentation, including the OPPLAN, is its direct mapping to the MITRE ATT\&CK Enterprise framework.5 MITRE ATT\&CK is the globally recognized industry-standard taxonomy for adversarial behaviors, cataloging tactics, techniques, and procedures based on real-world threat intelligence observations.20 By embedding MITRE mapping directly into the autonomous agent's decision matrix and operational plan, organizations ensure that the resulting attack telemetry aligns perfectly with the standard language used by modern defense systems, Security Information and Event Management (SIEM) platforms, and Threat-Informed Defense methodologies.21

While Decepticon approaches this via stateful LLM agency, several other specialized frameworks have historically paved the way for automated, MITRE-aligned adversary emulation. Understanding these platforms provides crucial context for the architectural innovations required to build truly autonomous red teams.

### **MITRE Caldera**

MITRE Caldera is a seminal open-source cybersecurity platform designed specifically to automate adversary emulation, assist manual red teams, and automate incident response, built directly upon the MITRE ATT\&CK framework.23 Caldera's architecture is highly modular, consisting of a core asynchronous command-and-control (C2) server with a REST API, supplemented by an extensive plugin ecosystem.23

These plugins represent discrete capabilities. The Access plugin handles initial access tools; Atomic integrates TTPs from the Atomic Red Team project; Sandcat provides the default agent functionality; and Stockpile serves as the storehouse for specific techniques and adversary profiles.23 Caldera operates by running specific, predefined "abilities" (scripts representing MITRE techniques) in a sequence dictated by an adversary profile. While highly effective for continuous validation and structured emulation, Caldera relies heavily on imperative execution. It executes scripts based on a predefined plan but lacks the declarative, cognitive ability to autonomously synthesize novel code, troubleshoot complex environmental errors on the fly, or engage in deep, open-ended social engineering without human intervention.

### **Prelude Operator**

Building upon the foundational research developed in Caldera, Prelude Operator utilizes previously unlicensed intellectual property from MITRE to offer a more accessible desktop application tailored for adversary emulation.22 Designed to close the cybersecurity gap for small and mid-sized organizations that struggle to hire highly qualified red team staff, Prelude allows these entities to evaluate their defenses against sophisticated adversaries.22 Similar to Caldera, Prelude is highly structured around the MITRE ATT\&CK matrix, focusing on bringing collaborative defense capabilities and advanced security knowledge to environments that cannot afford full-scale, human-led red team engagements.22

### **Scythe**

Scythe is a premium enterprise platform that bridges the gap between Cyber Threat Intelligence (CTI) and automated adversary emulation.21 Scythe allows operators to ingest threat intelligence reports and translate them into executable campaigns that mimic specific threat actors (e.g., the Conti ransomware group).21 This allows Security Operation Centers (SOCs) to tune their defenses against the precise TTPs they are most likely to encounter in their specific industry vertical.21 Scythe focuses heavily on the realistic emulation of malware behavior and C2 traffic, allowing organizations to validate their endpoint detection and response (EDR) solutions safely.

### **The Decepticon Agentic Approach**

Where Caldera, Prelude, and Scythe utilize structured automation and deterministic script execution, the Decepticon framework introduces genuine LLM-driven autonomy. Rather than executing a pre-written Python script for a specific MITRE technique, Decepticon understands the tactical intent of a MITRE ATT\&CK category (e.g., *OS Credential Dumping: LSASS Memory*) and autonomously determines the best tool, syntax, and evasion method required to achieve that outcome based on real-time environmental context.5 If a standard Mimikatz execution fails due to an updated Defender signature, Decepticon's agentic loop can autonomously search for alternative memory dumping techniques or attempt to disable the EDR process, pursuing the objective through whatever path opens up—exactly as a real attacker would.5

| Automation Framework | Core Architecture | Execution Paradigm | Primary Use Case | MITRE Integration |
| :---- | :---- | :---- | :---- | :---- |
| **MITRE Caldera** | Core C2 Server \+ Plugin Ecosystem 23 | Deterministic, Profile-based execution | Open-source adversary emulation and research 23 | Built natively on ATT\&CK; techniques stored in Stockpile.23 |
| **Prelude Operator** | Desktop Application (Built on Caldera IP) 22 | Deterministic, User-friendly interface | Bringing advanced emulation to SMBs and supply chains 22 | Deep integration utilizing licensed MITRE IP.22 |
| **Scythe** | Enterprise Threat Emulation Platform 21 | Campaign-based CTI emulation | validating SOC tuning against specific APT groups (e.g., Conti) 21 | Translates Threat Intelligence directly into TTP campaigns.21 |
| **Decepticon** | Multi-Agent LLM StateGraph 5 | Probabilistic, Goal-Directed Autonomy | Professional, autonomous red teaming with full pre-engagement docs 5 | MITRE ATT\&CK embedded in OPPLAN and Skill Middleware.5 |

## **Architectural Deep Dive: Orchestrating the Autonomous Kill Chain**

The execution of a complex OPPLAN mapped to MITRE ATT\&CK requires a sophisticated underlying software architecture capable of mimicking human cognitive flexibility while mitigating the inherent token-limit constraints of large language models. The Decepticon framework achieves this through a multi-agent, state-driven orchestration model built upon LangGraph.5

### **The Soundwave Documentation and Planning Agent**

In traditional LLM agent scaffolding, planning and execution are often conflated within a single prompt context. This leads directly to "prompt overflow" and severe context degradation as the agent attempts to hold both the high-level mission parameters and the granular, real-time terminal output of a network scan in its memory simultaneously.14

The Decepticon framework resolves this architectural flaw by utilizing a dedicated, interview-driven agent named Soundwave.6 Replacing an earlier, less specialized generic "Planner" agent, Soundwave acts as the operational commander strictly prior to execution.6 Operating via a web dashboard or CLI interface, Soundwave conducts an interactive interview with the human operator.6 It parses the target scope (IP ranges, URLs, Git repositories, or local file paths), determines the threat actor profile, and evaluates the allowed toolsets.15

Soundwave then autonomously generates the full suite of required documentation: RoE, ConOps, Deconfliction Plan, and the OPPLAN.5 A significant architectural evolution in recent builds (v1.0.8 onward) involves the total separation of planning ownership. Soundwave generates the OPPLAN and saves it directly to disk as a structured JSON file (plan/opplan.json).6

This file-based persistence solves a critical vulnerability in long-running autonomous operations: state recovery. Previously, if an agent crashed, encountered an API rate limit, or was intentionally halted by an operator, the in-memory state of the LangGraph execution was entirely lost, requiring a costly and time-consuming complete replanning phase.6 By hydrating the system state directly from the opplan.json file on startup, the main execution agent can resume exactly where it left off. The prompt is designed to check for the existence of this file upon initialization, calling the load\_opplan tool to skip re-planning entirely, avoiding objective ID collisions and saving substantial API token expenditure.6

### **Multi-Agent Topography and StateGraph Routing**

To manage the immense complexity of an end-to-end attack chain, the Decepticon framework utilizes an asynchronous LangGraph API-backed StateGraph router. This router explicitly governs operational phase transitions (ConOps → OPPLAN → Execution → Report) via conditional edges.6

Instead of relying on a monolithic LLM prompt that attempts to encompass all offensive capabilities, the framework deploys 16 highly specialized sub-agents.5 Each sub-agent is spawned with a fresh context window strictly specific to its assigned objective, preventing the accumulation of irrelevant terminal noise from prior phases.5 The orchestration layer can dispatch these sub-agents in parallel for tasks that lack strict blocked\_by dependencies, allowing simultaneous wide-scale reconnaissance and discrete exploit probing.6

The agent taxonomy is meticulously categorized across the phases of the cyber kill chain:

1. **Orchestration:** The Decepticon primary execution agent manages the overall flow, while Soundwave manages planning and documentation generation.5  
2. **Reconnaissance:** Dedicated Recon and Scanner agents handle target enumeration, service discovery, and external surface mapping.5  
3. **Exploitation Pipeline:** A highly structured sequence of agents handles vulnerability management: Exploit, Exploiter (validates vulnerabilities and executes PoCs), Detector (analyzes logs and signatures), Verifier, and Patcher.5  
4. **Post-Exploitation:** The Post-Exploit agent manages privilege escalation, credential harvesting, and lateral movement post-compromise.5  
5. **Specialist Roles:**  
   * **AD Operator:** Specialized in Active Directory exploitation, equipped with tools for BloodHound ingestion, Kerberoasting, AS-REP Roasting, ADCS ESC exploitation, and DCSync attacks.5  
   * **Cloud Hunter:** Dedicated to enumerating and analyzing AWS attack surfaces (IAM, S3, EC2, Lambda) and assessing Kubernetes RBAC misconfigurations.5  
   * **Contract Auditor:** Focused exclusively on Solidity smart contract security auditing.6  
   * **Reverser:** Handles binary analysis, entropy-based packer detection, and x86/x86\_64 ROP gadget finding utilizing Ghidra and radare2 scripts.5  
   * **Analyst:** Operates within specific hunting lanes, such as trust-boundary evaluation, pattern-exhaustion, or bounty target assessments.5  
6. **Defense:** The Defender agent executes tactical defensive actions as part of the Offensive Vaccine loop.5

### **Stateful Exploitation via Persistent Terminal Multiplexing**

A primary failure mode of rudimentary, stateless AI hacking tools is their total reliance on non-interactive, single-shot command execution.5 Real-world offensive operations require continuous, stateful interaction. Core tools such as Metasploit (msfconsole), Sliver C2 (sliver-client), and Windows remote management frameworks (evil-winrm) require persistent, interactive sessions.5 A stateless agent that fires a command via a REST API and passively waits for a standardized text response cannot effectively navigate the asynchronous nature of a reverse shell catching a callback or a multi-stage payload requiring secondary inputs.

Decepticon addresses this fundamental constraint by running every command inside persistent tmux (terminal multiplexer) sessions.5 The framework features advanced automatic prompt detection algorithms. When a payload execution successfully drops the agent into an interactive prompt (such as a compromised database shell, a Python interactive shell, or a meterpreter session), the agent recognizes the context shift. It can then transmit continuous, context-aware follow-up commands within that specific active session.5 This mechanism brilliantly bridges the gap between the stateless memory limitations of the underlying LLM and the deeply stateful, continuous requirements of network exploitation.5

## **Middleware Guardrails and Environmental Isolation**

Because an autonomous red team agent wields actual exploitation tooling—including capabilities that are inherently destructive or highly disruptive—implementing robust software guardrails and absolute network isolation is a critical engineering requirement. A single hallucination involving a recursive deletion command could compromise the testing environment or, worse, the production network.

### **The Triad of Security Middleware**

The internal execution engine of Decepticon relies on a triad of specialized middleware components to validate state transitions, parse context, and enforce strict operational security boundaries:

1. **OPPLANMiddleware:** This component handles the domain-specific Create, Read, Update, and Delete (CRUD) operations for the mission objectives within the OPPLAN.6 It strictly enforces state transition validation and dependency checking. For example, it algorithmically prevents a sub-agent from attempting lateral movement before initial access and privilege escalation objectives are definitively marked as successful.6 It additionally injects a dynamic battle tracker into the prompt context to keep the global state continuously updated.6  
2. **DecepticonSkillsMiddleware:** Operating as the critical interface between the cognitive LLM and the offensive toolkit, this middleware integrates MITRE ATT\&CK awareness directly into the skill execution system.6 It utilizes a progressive disclosure mechanism, rigorously controlled by allowed-tools fields defined in YAML frontmatter within the skill definition files.6 This ensures that an agent is only exposed to tools strictly relevant to its current operational phase, thereby optimizing token usage, minimizing API costs, and drastically reducing the probability of tool-use hallucinations.6  
3. **SafeCommandMiddleware:** This security layer acts as the ultimate OPSEC backstop. It intercepts raw shell commands generated by the LLM prior to passing them to the execution environment.6 It maintains an expanded, hardcoded blocklist designed specifically to catch session-destroying commands. Commands such as pkill, killall, rm \-rf /, nsenter, and nested docker exec calls are intercepted and blocked, returning an error to the agent to rethink its approach.6 This ensures that an anomalous algorithmic hallucination does not inadvertently destroy the terminal multiplexer session, the sandbox container, or the target environment.6

### **Network Architecture and Air-Gapped Infrastructure Isolation**

A defining characteristic of professional automated assessments—separating them entirely from localized scripts—is the physical and logical isolation of operational infrastructure from the management planes. If a target is compromised, or if a threat actor intercepts the payload, the compromised entity must not be able to pivot back into the LLM orchestration logic or access API keys.

The Decepticon architecture enforces this by physically separating the operational environment into two distinct Docker networks with zero routing permitted between them.5 The LLM gateway routing, PostgreSQL databases (managed via Prisma ORM), the Next.js 16 web dashboard, and the core LangGraph API logic reside securely on the management network (decepticon-net).5 Conversely, the fully equipped Kali Linux sandbox (housing the offensive toolchain, Ghidra scripts, BloodHound ingestors, etc.), the Sliver C2 server, and the designated target containers exist exclusively on the operational network (sandbox-net).5

The orchestrator exercises control over the sandbox strictly via the Docker socket. Because there is no exposed network port linking the operational network to the management infrastructure, the environments remain effectively "air-gapped".5 This architectural approach perfectly mimics the infrastructure of sophisticated Advanced Persistent Threats (APTs) who utilize complex redirectors and proxy chains to shield their core command-and-control servers from discovery by incident responders.

## **The LLM Ecosystem and Dynamic Provider Integration**

The tactical efficacy of any autonomous agent is inextricably linked to the reasoning capabilities, context window depth, and coding proficiency of its underlying language model. Because models vary wildly in their ability to write exploit code, parse complex JSON structures (like the opplan.json), and exhibit long-term strategic reasoning across a kill chain, flexibility in provider selection is paramount.

The Decepticon framework implements a sophisticated, credentials-aware, tier-based fallback chain governed by a DECEPTICON\_AUTH\_PRIORITY configuration matrix.6 The orchestrator dynamically inspects which credentials or API keys the operator has provided and orders the fallback routing accordingly, ensuring maximum uptime during operations.6 Out-of-the-box integration spans an extensive array of frontier models, ensuring operators are not locked into a single ecosystem.15 This includes native API access to Anthropic (with compatibility layers specifically resolving prompt refusals from Claude 4.x classifiers), OpenAI, Google Gemini, DeepSeek (including DeepSeek V4 Pro, supporting native reasoning\_content streaming for advanced logical parsing), xAI, and Mistral.6 It additionally supports specialized model aggregators like OpenRouter and NVIDIA NIM (hosting Llama 3.3 and Nemotron 70B).6

Crucially, the architecture also supports robust Subscription OAuth flows. This allows operators to leverage fixed-cost consumer or enterprise subscriptions (e.g., ChatGPT Pro, Claude Pro, Perplexity Pro) via specialized OAuth routing.5 This completely mitigates the risk of incurring exorbitant per-token API billing during massive, data-heavy reconnaissance runs where gigabytes of network traffic might be analyzed.15 For defense contractors, government agencies, or healthcare environments requiring absolute data sovereignty—where transmitting highly classified network telemetry to an external cloud API is legally prohibited—the framework seamlessly integrates with locally hosted models via Ollama. It utilizes parallel fan-out API tags for local capability checks to ensure the local model can adequately handle the tool-calling requirements before dispatching complex objectives.6

## **The "Offensive Vaccine": Closing the Autonomous Threat Loop**

The traditional endpoint of a red team engagement, penetration test, or vulnerability scan is the delivery of a static PDF report, a CSV file, or a dashboard of findings. The actual remediation process is left entirely to the defending organization's IT and security teams. In modern enterprise environments, this creates a significant latency period between the discovery of a critical vulnerability and the deployment of a patch, providing adversaries with a prolonged window of opportunity.8

The Decepticon framework introduces a revolutionary concept termed the "Offensive Vaccine," which fundamentally transforms the static outputs of a red team operation into immediate, machine-driven, dynamic defense enhancements.5 Operating under the core philosophy that offensive capabilities must strictly serve defensive improvements, the framework utilizes an automated Attack → Defend → Verify feedback loop, governed by the Vaccine Orchestrator component.6

### **The Automated Vulnerability Research and Remediation Pipeline**

When the initial offensive agents (such as Recon or Exploit) successfully discover a vulnerability and confirm access, the state is passed to a dedicated vulnerability research pipeline. This pipeline involves sequential, stateful handoffs between specialized sub-agents: the Scanner identifies the port, the Detector analyzes the application logic and signatures, the Exploiter generates and validates the Proof-of-Concept (PoC) exploit, the Patcher proposes a fix, and the Verifier confirms the remediation.5 This pipeline handles the full lifecycle of the vulnerability from initial discovery through proof-of-concept to actionable patch proposal.5

Once a valid exploit path is verified, the system seamlessly transitions into the active defense phase. The specialized Defender agent is dispatched to execute tactical defensive actions directly on the target infrastructure via an integrated AbstractDefenseBackend.6 This backend implements infrastructure-level interventions via Docker implementations. The Defender agent can autonomously deploy rapid firewall rules, execute precise port blocking, and apply service hardening configurations on the fly to neutralize the threat path discovered just milliseconds prior.6

### **Verification and the Neo4j Knowledge Graph**

Applying a patch or blocking a port does not guarantee comprehensive remediation, especially against complex bypass techniques or chained vulnerabilities. Therefore, the loop is not closed until the Verifier agent re-attacks the target.6 The Verifier utilizes the exact original OPPLAN parameters and exploit techniques to confirm that the defensive action holds against persistent attack.6

Crucially, every action taken, every prompt generated, and every command executed throughout this entire lifecycle is systematically logged into a persistent Neo4j Knowledge Graph.6 Instead of flat log files or disconnected SIEM alerts, the framework constructs a dimensional attack graph, visualizing the exact, granular pathways of compromise. When the Defender agent successfully implements a mitigation, new DefenseAction nodes are mathematically generated in the graph.6 These nodes are linked via explicit edge relationships—such as MITIGATES, DEFENDS, and RESPONDS\_TO—directly against the original attack nodes that represented the vulnerability.6

Furthermore, static analysis findings via SARIF (Static Analysis Results Interchange Format) files can be ingested directly into this graph.6 This integration creates a unified, topological view of the environment, linking deep code-level vulnerabilities directly to operational network weaknesses. This continuous, consent-based simulation on internal infrastructure enables security teams to identify, validate, prioritize, and remediate vulnerabilities at machine speed, shifting the paradigm from a reactive patching posture to an immune system-like, self-hardening architectural state.5

## **Systemic Integration and Operator Observability**

While the agentic framework is designed to operate with a high degree of autonomy, Human-in-the-Loop (HITL) oversight remains essential for ethical, legal, and operational reasons. Integrating automated findings with human-led red team reviews ensures that complex, context-dependent risks—such as the nuanced legal implications of a data exfiltration simulation involving simulated Protected Health Information (PHI)—are appropriately interpreted by human analysts.17

The framework provides profound observability into the agent's cognition, decision-making processes, and physical actions. Operators can view real-time execution streams via the Next.js web dashboard, which utilizes continuous Server-Sent Events (SSE) directly from the LangGraph backend.6 The dashboard provides distinct, highly organized views: a Live chat stream for observing Soundwave generation and sub-agent execution, a Plan viewer for monitoring OPPLAN objective tree progress, structured tabs for the engagement documents (RoE, ConOps, Deconfliction), a Findings tab parsing FIND-NNN.md reports generated within the engagement workspace, and the interactive Neo4j attack-chain visualization powered by React Flow.6

Moreover, the system accommodates direct, precise operator intervention. Utilizing proper pause, resume, and message-queuing mechanics, an operator can issue a soft halt (a single Ctrl+C command) during an active agent stream.6 The execution pauses precisely at the current state checkpoint, preserving the entire operational context.6 The operator can then inject specific guidance, alter objectives via the OPPLANMiddleware, or provide tactical feedback before resuming the operation, ensuring that the machine's immense velocity is constantly tethered to human strategic intent.6

A robust observability layer additionally captures per-agent performance metrics, LangSmith tracing integration for LLM cost analysis, and detailed activity logs for exhaustive post-engagement timeline reconstruction.6 Finally, reporting outputs are auto-generated into industry-standard formats, such as HackerOne-style Markdown renderers and Bugcrowd CSV submission formats, seamlessly bridging the gap between autonomous vulnerability discovery and traditional corporate vulnerability management workflows.6

## **Second and Third-Order Implications for the Cybersecurity Ecosystem**

The transition from human-driven red teaming and deterministic scanning to highly capable, stateful autonomous adversarial emulation introduces profound, multi-dimensional ripple effects across the global cybersecurity ecosystem.

### **The Escalation of Machine-Speed Warfare and Defensive Adaptation**

The most immediate and critical consequence is the drastic compression of the time-to-exploit window. Historically, enterprise defenders relied heavily on the implicit assumption that attackers face significant logistical hurdles. Reconnaissance takes time, crafting custom exploits to bypass specific EDR configurations is labor-intensive, and maintaining lateral movement without triggering heuristic detection requires deep, specialized human expertise. Autonomous agents capable of dynamically chaining TTPs at scale completely remove these friction points. As threat actors increasingly weaponize open-source agentic AI and deploy their own uncensored models, the sheer volume, speed, and sophistication of attacks will exponentially outpace manual detection and response capabilities.3

By proactively deploying autonomous red teams internally, organizations can subject their own defensive postures to continuous, live adversarial signals.10 This capability forces defensive AI systems to train and optimize against realistic, adaptive attacker behavior under conditions of uncertainty, rather than relying on assumed historical attack patterns or static benchmark datasets that rapidly succumb to model drift.2 It creates an evolutionary pressure cooker within the enterprise environment, forcing the SOC to operate at machine speed.

### **Navigating Kinetic Friction and Regulatory Governance**

However, this paradigm shift introduces the severe and novel risk of automated, kinetic network conflict. When a fast-moving Autonomous Red Team (ART) intersects with a highly reactive Autonomous Blue Team (ABT) within a live enterprise production environment, the resulting interaction can quickly spiral out of control. If an ABT detects anomalous reconnaissance and automatically revokes credentials based on a misclassified signal, an ART might interpret this as a standard defensive block and rapidly escalate to highly aggressive and noisy brute-force attempts or mass service enumeration to maintain its assigned foothold.2 This rapid-fire machine combat creates a chaotic feedback loop—defined as kinetic friction—that can easily paralyze critical business operations, lock out legitimate personnel, and cause cascading systemic failures far worse than the original simulated vulnerability.2

Consequently, the necessity for robust Deconfliction Plans and explicit, immutable RoE constraints becomes paramount. In the age of autonomous systems, these documents are no longer merely administrative checkboxes required for compliance; they are the fundamental algorithmic governors that prevent autonomous agents from destroying the digital ecosystems they are designed to test.4

Furthermore, in highly regulated industries such as healthcare, critical infrastructure, and global finance, AI explainability is an absolute legal mandate.2 Governing bodies and compliance auditors require a strict, provable chain of causality for all security events. The detailed state-tracking mechanisms provided by tools like OPPLANMiddleware, file-based JSON persistence, and the granular Neo4j graph relationships allow auditors to mathematically trace the exact lineage of every autonomous decision. This reconciles the sheer speed and complexity of machine-speed action with the immovable requirements of human governance, accountability, and legal standing.2

### **The Democratization of the Adversarial Perspective**

Ultimately, the proliferation of open-source automation frameworks deeply integrated with standard taxonomies like MITRE ATT\&CK democratizes advanced offensive capabilities. Previously, only the largest, best-resourced Fortune 500 organizations, intelligence agencies, or elite financial institutions could afford to maintain continuous, full-scale, human-led red team operations.22

By synthesizing the deep, specialized expertise required to execute complex TTPs into accessible, model-agnostic middleware, frameworks like Decepticon enable smaller entities, supply-chain vendors, and resource-constrained IT departments to adopt a highly mature, threat-informed defense posture.21 This forces the entire cybersecurity industry to elevate its defensive baseline, as relying on security through obscurity or the historically prohibitive financial cost of launching a sophisticated cyberattack is no longer a viable operational security strategy in an era where advanced persistent threats can be emulated by open-source, containerized AI agents.

## **Conclusion**

The deployment of stateful, autonomous red team agents represents a permanent and structural shift in how offensive cybersecurity is operationalized. Traditional vulnerability scanners and deterministic Breach and Attack Simulation platforms, while remaining useful for basic infrastructure hygiene and compliance tracking, are fundamentally ill-equipped to uncover the probabilistic vulnerabilities and complex, multi-stage attack chains characteristic of modern cloud environments and AI deployments.

By demanding the precise operational discipline expected of elite human red teams—specifically the mandatory generation of strict Rules of Engagement, comprehensive Concepts of Operations, real-time Deconfliction Plans, and granular, MITRE-mapped Operations Plans prior to any network interaction—frameworks like Decepticon separate professional adversary emulation from reckless, unconstrained script automation. Through the innovative integration of stateful interactive terminal multiplexers, absolute network isolation, multi-agent phase routing via conditional graphs, and the groundbreaking "Offensive Vaccine" Attack-Defend-Verify loop, the architecture resolves the inherent cognitive and temporal limitations of stateless language models. As the global cybersecurity landscape inevitably evolves into a continuous theater of machine-speed conflict, the integration of constrained, objective-driven, and meticulously documented autonomous adversaries will become an indispensable component of resilient, self-hardening enterprise defense.

#### **Works cited**

1. Red teaming vs. penetration testing vs. vulnerability scanning: what AI security teams actually need \- Repello AI, accessed on May 5, 2026, [https://repello.ai/blog/ai-red-teaming-vs-penetration-testing](https://repello.ai/blog/ai-red-teaming-vs-penetration-testing)  
2. Autonomous Red vs Blue Teaming: A New Frontier in Cybersecurity Risk and Reward, accessed on May 5, 2026, [https://www.isaca.org/resources/news-and-trends/industry-news/2026/autonomous-red-vs-blue-teaming-a-new-frontier-in-cybersecurity-risk-and-reward](https://www.isaca.org/resources/news-and-trends/industry-news/2026/autonomous-red-vs-blue-teaming-a-new-frontier-in-cybersecurity-risk-and-reward)  
3. Comparing AI Agents to Cybersecurity Professionals in Real-World Penetration Testing, accessed on May 5, 2026, [https://arxiv.org/html/2512.09882v1](https://arxiv.org/html/2512.09882v1)  
4. Introduction to Red Team Operations | by Azefox innovations \- Medium, accessed on May 5, 2026, [https://medium.com/@azefox/introduction-to-red-team-operations-3168caa74526](https://medium.com/@azefox/introduction-to-red-team-operations-3168caa74526)  
5. PurpleAILAB/Decepticon: Autonomous Hacking Agent for Red Team \- GitHub, accessed on May 5, 2026, [https://github.com/PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon)  
6. Releases · PurpleAILAB/Decepticon \- GitHub, accessed on May 5, 2026, [https://github.com/PurpleAILAB/Decepticon/releases](https://github.com/PurpleAILAB/Decepticon/releases)  
7. Red teaming vs penetration testing vs vulnerability scanning \- Securance, accessed on May 5, 2026, [https://www.securance.com/blog/redteaming-pentesting-vulnerabilityscanning](https://www.securance.com/blog/redteaming-pentesting-vulnerabilityscanning)  
8. Healthcare Red Team Operation: How to Test and Strengthen Your Organization's Cybersecurity \- Accountable HQ, accessed on May 5, 2026, [https://www.accountablehq.com/post/healthcare-red-team-operation-how-to-test-and-strengthen-your-organization-s-cybersecurity](https://www.accountablehq.com/post/healthcare-red-team-operation-how-to-test-and-strengthen-your-organization-s-cybersecurity)  
9. Red Teaming in 2026: The Bleeding Edge of Security Testing | CyCognito, accessed on May 5, 2026, [https://www.cycognito.com/learn/red-teaming/](https://www.cycognito.com/learn/red-teaming/)  
10. What Is a Red Team Agent in Agentic AI MDR? \- Deepwatch, accessed on May 5, 2026, [https://www.deepwatch.com/glossary/red-team-agent-in-agentic-ai-mdr/](https://www.deepwatch.com/glossary/red-team-agent-in-agentic-ai-mdr/)  
11. Stateless vs Stateful AI Agents Explained \- Medium, accessed on May 5, 2026, [https://medium.com/@vasanthancomrads/stateless-vs-stateful-ai-agents-explained-6cebfa80c253](https://medium.com/@vasanthancomrads/stateless-vs-stateful-ai-agents-explained-6cebfa80c253)  
12. From Stateless Queries to Autonomous Actions: A Layered Security Framework for Agentic AI Systems \- arXiv, accessed on May 5, 2026, [https://arxiv.org/html/2604.23338v1](https://arxiv.org/html/2604.23338v1)  
13. Stateful vs Stateless AI Agents: Architecture Guide, accessed on May 5, 2026, [https://www.ruh.ai/blogs/stateful-vs-stateless-ai-agents](https://www.ruh.ai/blogs/stateful-vs-stateless-ai-agents)  
14. Stateful vs Stateless AI Agents: A Practical Comparison | Tacnode Blog, accessed on May 5, 2026, [https://tacnode.io/post/stateful-vs-stateless-ai-agents-practical-architecture-guide-for-developers](https://tacnode.io/post/stateful-vs-stateless-ai-agents-practical-architecture-guide-for-developers)  
15. Decepticon/docs/getting-started.md at main \- GitHub, accessed on May 5, 2026, [https://github.com/PurpleAILAB/Decepticon/blob/main/docs/getting-started.md](https://github.com/PurpleAILAB/Decepticon/blob/main/docs/getting-started.md)  
16. JP 2-01.1, Joint Tactics, Techniques, and Procedures for Intelligence Support to Targeting \- Berlin Information-center for Transatlantic Security, accessed on May 5, 2026, [https://www.bits.de/NRANEU/others/jp-doctrine/jp2\_01\_1.pdf](https://www.bits.de/NRANEU/others/jp-doctrine/jp2_01_1.pdf)  
17. Automated Red Teaming: Capabilities, Pros/Cons, and Latest Trends \- Mend.io, accessed on May 5, 2026, [https://www.mend.io/blog/automated-red-teaming-capabilities-pros-cons-and-latest-trends/](https://www.mend.io/blog/automated-red-teaming-capabilities-pros-cons-and-latest-trends/)  
18. Red Team Engagements | Tryhackme Writeup/Walkthrough | By Md Amiruddin, accessed on May 5, 2026, [https://infosecwriteups.com/red-team-engagements-tryhackme-writeup-walkthrough-by-md-amiruddin-8870be21f164](https://infosecwriteups.com/red-team-engagements-tryhackme-writeup-walkthrough-by-md-amiruddin-8870be21f164)  
19. Targeting, Air Force Doctrine Document 2-1.9 \- DTIC, accessed on May 5, 2026, [https://apps.dtic.mil/sti/tr/pdf/ADA454614.pdf](https://apps.dtic.mil/sti/tr/pdf/ADA454614.pdf)  
20. MITRE ATT\&CK®, accessed on May 5, 2026, [https://attack.mitre.org/](https://attack.mitre.org/)  
21. SCYTHE Library: Simplifying the MITRE ATT\&CK Framework, accessed on May 5, 2026, [https://scythe.io/library/simplifying-the-mitre-att-ck-framework](https://scythe.io/library/simplifying-the-mitre-att-ck-framework)  
22. MITRE and Prelude Announce Partnership to Offer Advanced Cybersecurity for Small and Mid-sized Organizations, accessed on May 5, 2026, [https://www.mitre.org/news-insights/news-release/mitre-and-prelude-announce-partnership-offer-advanced-cybersecurity](https://www.mitre.org/news-insights/news-release/mitre-and-prelude-announce-partnership-offer-advanced-cybersecurity)  
23. mitre/caldera: Automated Adversary Emulation Platform \- GitHub, accessed on May 5, 2026, [https://github.com/mitre/caldera](https://github.com/mitre/caldera)  
24. MITRE Caldera, accessed on May 5, 2026, [https://caldera.mitre.org/](https://caldera.mitre.org/)  
25. Decepticon/docs/agents.md at main · PurpleAILAB/Decepticon, accessed on May 5, 2026, [https://github.com/PurpleAILAB/Decepticon/blob/main/docs/agents.md](https://github.com/PurpleAILAB/Decepticon/blob/main/docs/agents.md)  
26. Decepticon/docs/architecture.md at main · PurpleAILAB/Decepticon, accessed on May 5, 2026, [https://github.com/PurpleAILAB/Decepticon/blob/main/docs/architecture.md](https://github.com/PurpleAILAB/Decepticon/blob/main/docs/architecture.md)  
27. We're building autonomous pentesting agents and need honest feedback from security professionals : r/cybersecurity \- Reddit, accessed on May 5, 2026, [https://www.reddit.com/r/cybersecurity/comments/1sfte99/were\_building\_autonomous\_pentesting\_agents\_and/](https://www.reddit.com/r/cybersecurity/comments/1sfte99/were_building_autonomous_pentesting_agents_and/)  
28. Red Teaming vs Penetration Testing: Understanding the Differences | Synack, accessed on May 5, 2026, [https://www.synack.com/knowledge-base/red-teaming-vs-penetration-testing-understanding-the-differences/](https://www.synack.com/knowledge-base/red-teaming-vs-penetration-testing-understanding-the-differences/)