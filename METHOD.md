# Foundation — STAMP, STPA, and the security adaptation

Theory and canonical definitions. Everything in the "Handbook doctrine" sections below was read directly from the STPA Handbook PDF (Leveson & Thomas, March 2018) during authoring; quoted definitions are verbatim from it. Sections marked **[toolkit extension]** are this toolkit's additions and are **not** STPA doctrine — the distinction is maintained deliberately so nobody cites us as if we were Leveson.

---

## STAMP — the causality model underneath

STPA is the hazard-analysis technique; **STAMP** (Systems-Theoretic Accident Model and Processes), Nancy Leveson's accident causality model, is what it rests on.

**STAMP is a model, not a method.** Handbook p.12: *"STAMP is not an analysis method. Instead it is a model or set of assumptions about how accidents occur."* STPA (proactive) and CAST (retrospective accident analysis) are the two tools built on it. Never conflate the three: STAMP = the causality model, STPA = the method, STPA-Sec = the security framing of the method.

The founding claim: **losses result from inadequate control, not only from component failure.** Traditional hazard analysis (fault trees, FMEA, HAZOP) and traditional threat modeling both assume a loss traces back to something breaking. STAMP holds that a system composed of components each meeting its specification can still be unsafe, because safety is an *emergent property of the interactions*, enforced — or not — by a control structure.

The Handbook states this directly when explaining why STPA's hazards must be abstract: *"Hazard identification in STPA is about system states and conditions that are inherently unsafe—regardless of the cause. In fact, the system hazards should be specified at a high-enough level that does not distinguish between causes related to technical failures, design errors, flawed requirements, or human procedures and interactions."*

Three core concepts carry the model:

1. **Safety constraints** — safety is a control problem: the system must be constrained from reaching hazardous states.
2. **Hierarchical control structures** — systems are modeled as layered feedback control loops, each level imposing constraints on the level below. The Handbook: *"A hierarchical control structure is a system model that is composed of feedback control loops. An effective control structure will enforce constraints on the behavior of the overall system."*
3. **Process models** — every controller acts on internal beliefs about the system. The Handbook: *"Controllers also have process models that represent the controller's internal beliefs used to make decisions… Problems can occur at any point… For example, a process model that is not consistent with reality… can lead to control actions that are unsafe."*

Two more framing quotes worth having verbatim. On the reframe, p.12: *"In STAMP, safety is treated as a dynamic control problem rather than a failure prevention problem"* — the emphasis shifts *"from preventing failures to enforcing constraints on system behavior."* And on why using it for security is not a stretch, p.12: **"Because STAMP applies to any emergent property, STPA can be used for any system property, including cybersecurity."** The chain-of-failure-events model is explicitly *"a subset of STAMP"*, so STAMP-based tools capture what the traditional techniques capture, plus more.

The generic control loop — Controller (Control Algorithm + Process Model) → Control Actions → Controlled Process, with Feedback returning — is the unit of analysis. Actuators sit on the control path; sensors sit on the feedback path.

---

## The four steps (Handbook doctrine)

1. **Define Purpose of the Analysis** — identify losses, identify system-level hazards, identify system-level constraints, refine hazards (optional).
2. **Model the Control Structure**
3. **Identify Unsafe Control Actions**
4. **Identify Loss Scenarios**

The Handbook notes STPA is iterative: *"STPA is iterative and need not be performed in a strictly linear fashion—earlier results can be updated as the analysis progresses."*

---

## Definitions (verbatim from the Handbook)

> **Loss** — "A *loss* involves something of value to stakeholders. Losses may include a loss of human life or human injury, property damage, environmental pollution, loss of mission, loss of reputation, loss or leak of sensitive information, or any other loss that is unacceptable to the stakeholders."

> **Hazard** — "A *hazard* is a system state or set of conditions that, together with a particular set of worst-case environmental conditions, will lead to a loss."

> **System** — "A *system* is a set of components that act together as a whole to achieve some common goal, objective, or end. A system may contain subsystems and may also be part of a larger system."

> **System-level constraint** — "A system-level constraint specifies system conditions or behaviors that need to be satisfied to prevent hazards (and ultimately prevent losses)."

> **Hierarchical control structure** — "A hierarchical control structure is a system model that is composed of feedback control loops. An effective control structure will enforce constraints on the behavior of the overall system."

> **Unsafe Control Action (UCA)** — "An Unsafe Control Action (UCA) is a control action that, in a particular context and worst-case environment, will lead to a hazard."

> **Controller constraint** (p.41) — "A controller constraint specifies the controller behaviors that need to be satisfied to prevent UCAs."

> **Loss scenario** — "A loss scenario describes the causal factors that can lead to the unsafe control actions and to hazards."

The **controller constraint** is the hinge this toolkit hangs on: it is generated in Step 3 by inverting each UCA, and it is the object that `Workflows/SecurityConstraints.md` maps onto a testable security assertion. Handbook example: UCA-2 → *"C-2: BSCU Autobrake must not provide Brake control action during a normal takeoff [UCA-2]."*

The Handbook footnotes that *"unsafe"* is scoped to whatever losses you declared: *"hazards can include issues related to loss of human life or injury (traditional safety) but they can also be defined much more broadly to include other losses like a mission loss, loss of performance, environmental losses, etc."* — which is precisely what licenses using STPA for security.

---

## Writing hazards correctly (Handbook doctrine)

The Handbook's three criteria for a system-level hazard:

- Hazards are **system** states or conditions (not component-level causes or environmental states)
- Hazards **will** lead to a loss in some worst-case environment
- Hazards must describe **states or conditions to be prevented**

Its hazard specification form:

```
<Hazard specification> = <System> & <Unsafe Condition> & <Link to Losses>
e.g.  H-1 = Aircraft  violate minimum separation standards in flight  [L-1, L-2, L-4, L-5]
```

And the system-level constraint is a mechanical inversion:

```
<System-level Constraint> = <System> & <Condition to Enforce> & <Link to Hazards>
SC-1: Aircraft must satisfy minimum separation standards from other aircraft and objects [H-1]
```

Constraints may also take the mitigation form: *"<System-level Constraint> = If <hazard> occurs, then <what needs to be done to prevent or minimize a loss> & <Link to Hazards>"*.

### Common mistakes the Handbook names

The Handbook's own tip box, verbatim:

> - Hazards should not refer to individual components of the system
> - All hazards should refer to the overall system and system state
> - Hazards should refer to factors that can be controlled or managed by the system designers and operators
> - All hazards should describe system-level conditions to be prevented
> - The number of hazards should be relatively small, usually no more than 7 to 10
> - Hazards should not include ambiguous or recursive words like "unsafe", "unintended", "accidental", etc.

Named failure modes: **confusing hazards with causes of hazards** ("brake failure", "operator is distracted" are causes, not hazards); **too many hazards containing unnecessary detail** (7–10 is the rule of thumb; refine into sub-hazards instead); **ambiguous or recursive wording** (using "unsafe" inside a hazard is a recursive definition); **confusing hazards with failures** (STPA hazards are about states that are inherently unsafe regardless of cause).

For losses, the Handbook adds: *"Losses should not reference individual components or specific causes like 'human error' and 'brake failure'"*, and *"Document any special considerations or assumptions made, such as losses that are explicitly excluded."*

---

## The four UCA types (Handbook doctrine)

Verbatim:

> 1. Not providing the control action leads to a hazard.
> 2. Providing the control action leads to a hazard.
> 3. Providing a potentially safe control action but too early, too late, or in the wrong order
> 4. The control action lasts too long or is stopped too soon (for continuous control actions, not discrete ones).

**It is exactly four, and the Handbook claims completeness:** *"These four categories are provably complete—there is no other category of unsafe control action."* Subcategories exist under type 2, which the Handbook enumerates: contexts where the action is never safe; **incorrect parameter**; **insufficient, excessive, or repetitive** application; **wrong direction**; **already provided** (repetitive, oscillatory, intermittent); **provided too quickly or too slowly**.

Type 4 applies only to control actions with a duration. Where an action is modeled as two discrete actions (Start / Stop), the same issues are captured by type 3 on each.

Not every type yields a UCA: *"each category may contain 0, 1, 2, or more UCAs."* But all four must be *considered*.

### The five-part UCA form (Handbook doctrine)

```
UCA-2: BSCU Autobrake   provides   Brake command   during a normal takeoff   [H-4.3]
        <Source>        <Type>     <Control Action>    <Context>         <Link to Hazards>
```

Ordering is not critical; containing all five parts is. The Handbook stresses the context: *"If a control action were always unsafe, then it probably would not have been designed into the system to begin with. Every UCA must specify under what conditions (in what context) the control action is unsafe."*

**Two errors the Handbook explicitly warns about — both easy to make in software:**

1. **Do not put the result in place of the context.** ✗ *"BSCU Autobrake provides Brake command resulting in a collision."* ✓ *"…during a normal takeoff [H-4.3]."*
2. **Do not put the controller's belief in the context.** The context must be the **actual, true** state, not a process-model flaw. ✗ *"…provides Brake command when it incorrectly believes the aircraft is landing."* ✓ *"…provides Brake command during normal takeoff."* Process-model flaws are **causes**, and causes belong to Step 4.

That second rule matters enormously here, because "the controller believed the wrong thing" is the most natural way to describe a software authorization bug. Say it in Step 4, not in the UCA.

Also from the Handbook: **safeguards do not excuse a UCA.** *"STPA is a worst-case analysis method and we cannot omit UCAs when a safeguard exists."* And every UCA must trace to a hazard — a UCA that traces to none means you are probably missing a hazard.

Step 3's outputs are **Unsafe Control Actions** *and* **Controller Constraints** — the requirement-generation step happens here, not only at the end.

---

## Loss scenario causal factors (Handbook doctrine)

Two types of scenario must be considered:

> a) Why would Unsafe Control Actions occur?
> b) Why would control actions be improperly executed or not executed, leading to hazards?

### Part (a) — why UCAs occur

Four general reasons a controller provides (or fails to provide) an unsafe control action:

- **Failures involving the controller** (physical controllers)
- **Inadequate control algorithm** — flawed implementation; the specified algorithm is flawed; the algorithm becomes inadequate over time due to changes or degradation
- **Unsafe control input** from another controller
- **Inadequate process model** — which occurs when: controller receives incorrect feedback/information; controller receives correct feedback but interprets it incorrectly or ignores it; controller does not receive feedback when needed (delayed or never received); necessary feedback/information does not exist

Plus a second cluster, **causes of inadequate feedback and information**:

- **Feedback or information not received** — sent by sensor but not received by controller; not sent by sensor but received/applied to sensor; not received or applied to sensor; does not exist in the control structure or the sensors do not exist
- **Inadequate feedback is received** — sensors respond adequately but controller receives inadequate feedback; sensors respond inadequately; sensors are not capable or not designed to provide necessary feedback

### Part (b) — why control actions are improperly executed or not executed

**Scenarios involving the control path:**

- *Control action not executed* — sent by controller but not received by actuator; received but actuator does not respond; actuator responds but the action is not applied to or received by the controlled process
- *Control action improperly executed* — sent but received improperly; received correctly but actuator responds inadequately; actuator responds adequately but the action is applied/received improperly at the controlled process; **control action is not sent by the controller, but actuators or other elements respond as if it had been sent**

**Scenarios related to the controlled process:**

- Control action applied or received but the controlled process does not respond
- Control action applied or received but the controlled process responds improperly

The Handbook adds that control actions may also *"be overridden by other controllers"* — which in software is the bypass class.

### The Handbook's own security hook

Security is not bolted on from outside. The Handbook itself specifies where the adversary enters, in three places:

- On the control algorithm: *"identify if and how the control algorithm flaw could be introduced by an adversary."*
- On feedback: *"identify how the specified feedback and other information could be affected by an adversary. More specifically: how could they be injected, spoofed, tampered, intercepted, or disclosed to an adversary?"*
- On the control path: *"identify how the specified control action could be affected by an adversary. More specifically: how could it be injected, spoofed, tampered, intercepted, or disclosed to an adversary?"*

Its worked security example: *"The BSCU sends the Brake command, but the brakes are not applied because an adversary executes a denial of service attack that blocks the Brake command."*

**The adversary belongs in Step 4, not Step 3.** This is the load-bearing structural fact for security use, and it is the Handbook's own position: the *unsafe* set is defined by the design; the adversary explains *how you get there*.

---

## STPA-Sec — the security adaptation

**Young, W., & Leveson, N. G. (2014). "An Integrated Approach to Safety and Security Based on Systems Theory." *Communications of the ACM*, 57(2), 31–35.**

Quotes below are verbatim from the CACM paper.

**Safety and security are the same problem with different intent.** *"Safety experts see their role as preventing losses due to unintentional actions by benevolent actors. Security experts see their role as preventing losses due to intentional actions by malevolent actors. The key difference is the intent of the actor that produced the loss event."* So the problem is *"reframed as a general loss prevention problem that focuses on the aspects of the problem (such as the system design) that we have control over rather than immediately jumping to the parts about which we have little information, such as identifying all the potential external threats."*

**The thesis line:** *"The key question facing security analysts should be how to control vulnerabilities, not how to avoid threats."*

**Vulnerability ↔ hazard:** *"Hazards lead to safety incidents in the same way that vulnerabilities lead to security incidents."* Vulnerabilities *"are likely far fewer than threats and, if controlled, can prevent losses due to numerous types of threats and disruptions."* Usage across the literature is not fully consistent, so **this toolkit uses "hazard" throughout** and says so rather than pretending the field has settled.

**Strategy before tactics:** *"Tactics is focused on physical threats, while strategy is focused on abstract outcomes."* *"In tactics models, losses are conceptualized as specific events caused by threats… tactics models treat the threat as the cause of the loss."* The alternative: *"a top-down, strategic approach starts with identifying the system losses that are unacceptable and against which the system must be protected."*

**Why they argue this beats threat enumeration:** threat-based defense *"is heavily dependent on the degree to which security analysts can correctly identify potential attackers — their motives, capabilities, and targeting"*, and they name three problems — *"quantity, threat variety, and threat prioritization."* *"If the defense is optimized against the wrong threat, then the barriers may be ineffective."* Controlling vulnerabilities instead covers *"unknown threats, such as insiders."*

**Honest reading — they do not discard threat modeling.** *"The new approach does not discard traditional security thinking, but does suggest it is tactically focused and must be augmented by an effective strategy."* Anyone citing STPA-Sec as "STRIDE is obsolete" is overclaiming past the source.

### The delta, and why this toolkit is built the way it is

The single most important sentence for this artifact's architecture:

> *"STPA-Sec is an extension to STPA to include security analysis. The initial steps in the analysis are identical to those for safety… **The only difference is the addition of intentional actions in the generation of the causal scenarios, the last step in the process.**"*

That is Young & Leveson stating outright that **the adversary enters at Step 4, not Step 3** — which is exactly the structure `Workflows/IdentifyUCAs.md` and `Workflows/LossScenarios.md` implement, and it matches the Handbook's own three adversary hooks quoted above. The design choice is not this toolkit's invention; it is the method.

Their mechanism for the adversary is process-model corruption, illustrated with Stuxnet — the automation believed the centrifuges were spinning slower than they were and issued *Increase Speed* at maximum: *"Whether the inconsistency results from an inadvertent reason (accidental loss of feedback…) or tricking the controller… the result remains the same — an unsafe or unwanted control action."* This is the direct source for `SoftwareMapping.md`'s process-model-inconsistency lens.

**One thing still unverified.** A purpose statement of the form *"a system to do {what} by means of {how} in order to contribute to {why}"* is widely attributed to STPA-Sec and is used in `Workflows/ScopeAndLosses.md`. **[UNVERIFIED]** — it does not appear in the CACM paper; it most likely originates in Young's 2017 MIT dissertation or the ACSAC '13 paper (paywalled). Treat the phrasing as attributed-secondhand. It is a useful framing device regardless; just do not cite CACM for it.

**Related variants:** **STPA-SafeSec** (Friedberg, McLaughlin, Smith, Laverty & Sezer, *Journal of Information Security and Applications* 34:183–196, 2017) adds security constraints and maps the abstract control layer onto real components. **STPA-Priv** (Shapiro, IEEE S&P Workshops 2016) adapts it for privacy. **STPA-DFSec** (Yu, Wagner & Luo, arXiv:2006.02930) replaces the control structure with a data-flow interaction structure to catch confidentiality issues STPA-Sec misses. **Mission-aware STPA-Sec** (Carter, Bakirtzis, Elks & Fleming, arXiv:1711.00838) adds stakeholder elicitation. There are also published **STRIDE+STPA hybrids** — worth knowing, because the honest position is that the two are complementary, not rivals.

---

## Honest limitations

Stating these is not hedging — a method presented without its limits gets misapplied and then discarded.

1. **Effort cost.** STPA on a real system is hours-to-days of skilled analyst time. This is the most consistently reported barrier to adoption and it is real. Mitigation here: `Workflows/QuickTriage.md` and the deterministic tools.
2. **Analyst dependence.** The Handbook's own guidance is full of "common mistakes" sections precisely because results vary heavily with analyst skill. Two analysts produce different control structures for the same system. The method structures judgment; it does not replace it.
3. **No stopping rule, and the authors say so.** CACM 2014 concedes: *"such a list can never be proven to be complete — there is no formal (mathematical) model of the entire system… incompleteness will always be possible."* The four UCA *categories* are claimed provably complete; scenario enumeration beneath them is open-ended and analyst-terminated. **[toolkit extension]** `stpa init|status|grid` supplies a stopping rule by construction — the grid is exactly `4 × |control actions|` cells, coverage is a computed ratio, and a finding counts only when it binds to a declared control-structure element. That is our answer, not Leveson's, and it bounds the *categorical* sweep, not the scenario depth beneath it.
4. **No likelihood or probability ranking — by design.** The Handbook is explicit: *"STPA is a worst-case analysis method not a best-case, average-case, or most-likely-case method."* This is a deliberate feature that practitioners often experience as a limitation, because it makes prioritisation hard. **[toolkit extension]** `AdversarialContext.md` supplies a loss-severity × context-reachability heuristic. It is not a probability and not CVSS-comparable.
5. **Control-structure abstraction is the hard part and is under-specified.** The Handbook gives criteria for hazards but comparatively little procedure for choosing the granularity of the control structure. Too coarse and you find nothing; too fine and the grid explodes. This is where most software analyses go wrong.
6. **Scaling.** Grid size grows with the number of control actions, and a platform-wide analysis becomes unmanageable. Slice by trust boundary.
7. **No adversary capability model — a deliberate deferral with a real cost.** STPA-Sec defers threat characterization to *"limit the intelligence burden"*, which is right for finding design defects and wrong if you must argue *who* realistically attacks you and with what. The published comparison is blunt about the consequence: Kavallieratos et al. (*Computers & Security*, 2023 — the CyberShip study, comparing STPA-Sec vs STRIDE vs CORAS) find that with STPA-Sec *"many well-known cyber threats and vulnerabilities might not be covered, as threats and vulnerabilities that can compromise components cannot be identified at this stage"*, whereas STRIDE covers the security properties directly (C-I-A, authentication, authorization, non-repudiation). **Read that as an argument for running both**, which is why this toolkit's `NOT FOR` clause routes component-level and live testing elsewhere rather than claiming to subsume them.
8. **Specific peer-reviewed critiques of STPA-Sec.** Schmittner, Ma & Puschner (SAFECOMP 2016) report that STPA-Sec *"lacks guidance for intended causal scenarios, excludes considerations of the data exchange which is not directly connected to the process control and cannot cover more information-security centric properties such as confidentiality."* Torkildson, Li & Johnsen (ESREL 2019) find essential security issues can be overlooked and recommend pairing with data-flow threat models. Yu, Wagner & Luo concur: *"STPA-Sec lacks guidance for identifying security concepts."* The confidentiality gap is the one to internalize — STPA is strongest on integrity and authority, weakest on information flow.
9. **Empirical evidence is thinner than the rhetoric.** The red-team comparison against attack trees that CACM 2014 promised *"by spring 2014"* appears never to have been published **[UNVERIFIED]**. Leveson's own claim that STPA finds more scenarios at lower cost than FTA/FMECA/ETA/HAZOP (Handbook p.4) is the authors' summary of their own evaluations, and the Handbook deliberately omits citations. A Google STPA pilot — two engineers part-time for five months, reportedly identifying defects that would likely have prevented at least four major incidents — is an encouraging anecdote, not a controlled study. The argument in this toolkit's `SKILL.md` is therefore a **structural** one — checklists cannot find losses arising without component failure — not a claim about measured effect sizes.

---

## Tooling (external)

**XSTAMPP** — eXtensible STAMP Platform, University of Stuttgart (Abdulkhaleq & Wagner); open-source Eclipse/Java RCP with plug-ins for STPA, CAST, and STPA-Sec; successor to A-STPA. <https://github.com/SE-Stuttgart/XSTAMPP>. Also: **SafetyHAT** (US DOT Volpe, Access-based, transportation), **WebSTAMP** (web app for STPA and STPA-Sec), **SAHRA** (ZHAW).

This toolkit deliberately does not attempt to reimplement either. Its tools do the two things a general-purpose STPA tool does not: extract *software* control-structure candidates from a repository, and make coverage countable.

---

## Sources

- **STPA Handbook** — Leveson, N. G. & Thomas, J. P. (March 2018). *STPA Handbook*. Primary source; PDF read directly during authoring. <https://psas.scripts.mit.edu/home/get_file.php?name=STPA_handbook.pdf>
- **MIT Partnership for Systems Approaches to Safety and Security (PSAS)** — <https://psas.scripts.mit.edu/home/>
- **Young, W. & Leveson, N. G. (2014).** "Inside Risks: An Integrated Approach to Safety and Security Based on Systems Theory." *Communications of the ACM* 57(2), 31–35. DOI 10.1145/2556938. Full text read: <http://sunnyday.mit.edu/papers/cacm232.pdf>
- **Young, W. & Leveson, N. (2013).** "Systems thinking for safety and security." *Proc. ACSAC '13*, 1–8. DOI 10.1145/2523649.2530277 — <https://dl.acm.org/doi/10.1145/2523649.2530277> (paywalled; DOI verified).
- **Young, W. (2017).** *A System-Theoretic Security Analysis Methodology for Assuring Complex Operations Against Cyber Disruptions.* PhD dissertation, MIT (cited at Handbook p.56 fn.11).
- **Friedberg, McLaughlin, Smith, Laverty & Sezer (2017).** "STPA-SafeSec: Safety and security analysis for cyber-physical systems." *Journal of Information Security and Applications* 34(2), 183–196 — OA: <https://pureadmin.qub.ac.uk/ws/files/132972897/Stpa.pdf>
- **Yu, Wagner & Luo (2020).** "Data-Flow-Based Extension of STPA-Sec." arXiv:2006.02930 — <https://arxiv.org/pdf/2006.02930>
- **Carter, Bakirtzis, Elks & Fleming (2018).** "A systems approach for eliciting mission-centric security requirements." arXiv:1711.00838 — <https://arxiv.org/pdf/1711.00838>
- **Kavallieratos et al. (2023).** CyberShip — STPA-Sec vs STRIDE vs CORAS comparison. *Computers & Security* — <https://arxiv.org/pdf/2212.10830>
- **Schmittner, Ma & Puschner (2016).** "Limitation and Improvement of STPA-Sec for Safety and Security Co-analysis." SAFECOMP — <https://link.springer.com/chapter/10.1007/978-3-319-45480-1_16> (paywalled; critique points quoted via Yu et al. ref [26]).
- **Mylius, S. (2025).** "Systematic Hazard Analysis for Frontier AI using STPA." arXiv:2506.01782 — <https://arxiv.org/pdf/2506.01782>
- **Silawi et al. (2024).** "Translating the STPA-Sec Security Method into a Model-Based Engineering Approach." *INCOSE International Symposium* — <https://incose.onlinelibrary.wiley.com/doi/abs/10.1002/iis2.13249>
- **Applying STAMP to explore vulnerabilities: human and organisational factors in cybersecurity** — <https://publications.ergonomics.org.uk/uploads/Human-and-organisational-factors-in-cybersecurity-applying-STAMP-to-explore-vulnerabilities.pdf>
- **Hazard Analysis for Self-Adaptive Systems Using STPA** — <https://arxiv.org/pdf/2304.00408>
- **XSTAMPP** — <https://github.com/SE-Stuttgart/XSTAMPP>
