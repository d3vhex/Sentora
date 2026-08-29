/**
 * Windows event bodies, made readable without being falsified.
 *
 * The record must survive: this only decides what earns the one line a table
 * cell has. Anything it cannot parse is passed through rather than mangled by
 * a parser written for something else.
 *
 * Run:
 *   cd frontend
 *   npm test
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseEventMessage, summariseEventMessage } from './windowsEvent.ts';

// Verbatim from an agent, which is the point - this is the message an
// operator said nothing could be understood from.
const POWERSHELL_403 = [
  '[PowerShell] EID=403, Cat=4 | Stopped | Available | \tNewEngineState=Stopped',
  '\tPreviousEngineState=Available',
  '',
  '\tSequenceNumber=49',
  '',
  '\tHostName=ConsoleHost',
  '\tHostVersion=5.1.26100.9168',
  '\tHostId=b5b39b50-ce80-4a14-80d2-a3e6d6998a29',
  '\tHostApplication=powershell -NoProfile -Command [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-PnpDevice -PresentOnly | Select-Object FriendlyName, InstanceId | ConvertTo-Json',
  '\tEngineVersion=5.1.26100.9168',
  '\tRunspaceId=1be928aa-0165-4b1a-8fd5-eccb8c19ec8e',
  '\tPipelineId=',
  '\tCommandName=',
  '\tCommandType=',
  '\tScriptName=',
  '\tCommandPath=',
  '\tCommandLine=',
].join('\r\n');

describe('parseEventMessage', () => {
  test('separates the headline from the fields', () => {
    const parsed = parseEventMessage(POWERSHELL_403);
    assert.equal(parsed.structured, true);
    assert.ok(parsed.headline.startsWith('[PowerShell] EID=403'));
    assert.ok(!parsed.headline.endsWith('|'), 'trailing separators are trimmed');
  });

  test('drops the empty keys Windows emits on every event', () => {
    const parsed = parseEventMessage(POWERSHELL_403);
    const keys = parsed.fields.map((f) => f.key);
    for (const empty of ['PipelineId', 'CommandName', 'CommandType', 'ScriptName']) {
      assert.ok(!keys.includes(empty), `${empty} carried no value and should be dropped`);
    }
  });

  test('keeps every field that had a value', () => {
    const parsed = parseEventMessage(POWERSHELL_403);
    const keys = parsed.fields.map((f) => f.key);
    // The record must survive - a detail view shows all of these.
    for (const kept of ['NewEngineState', 'HostName', 'HostVersion', 'HostId',
                        'HostApplication', 'EngineVersion', 'RunspaceId']) {
      assert.ok(keys.includes(kept), `${kept} was lost`);
    }
  });

  test('a value containing = is not truncated at the first one', () => {
    const parsed = parseEventMessage(POWERSHELL_403);
    const host = parsed.fields.find((f) => f.key === 'HostApplication');
    assert.ok(host!.value.includes('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8'));
  });

  test('plain text is not treated as fields', () => {
    const parsed = parseEventMessage('Accepted password for root from 10.0.0.9 port 22');
    assert.equal(parsed.structured, false);
    assert.equal(parsed.fields.length, 0);
  });

  test('survives the shapes that actually arrive', () => {
    for (const input of ['', '   ', undefined as any, null as any, 42 as any]) {
      const parsed = parseEventMessage(input);
      assert.equal(parsed.structured, false);
    }
  });
});

describe('summariseEventMessage', () => {
  test('surfaces what was executed, not the GUIDs', () => {
    const line = summariseEventMessage(POWERSHELL_403);
    assert.ok(line.includes('HostApplication'), 'the useful field is missing');
    assert.ok(line.includes('Get-PnpDevice'), 'what ran should be visible');
    assert.ok(!line.includes('RunspaceId'), 'a GUID should not win the one line');
    assert.ok(!line.includes('1be928aa'), 'a GUID should not win the one line');
  });

  test('keeps the headline so the event is identifiable', () => {
    assert.ok(summariseEventMessage(POWERSHELL_403).includes('EID=403'));
  });

  test('is one line', () => {
    const line = summariseEventMessage(POWERSHELL_403);
    assert.ok(!line.includes('\n'));
    assert.ok(!line.includes('\t'));
  });

  test('respects the length limit', () => {
    const line = summariseEventMessage(POWERSHELL_403, 80);
    assert.ok(line.length <= 80, `got ${line.length}`);
  });

  test('a syslog line is passed through, not mangled', () => {
    const syslog = 'Aug 27 07:34:25 host sshd[991]: Accepted password for root from 10.0.0.9';
    assert.equal(summariseEventMessage(syslog), syslog);
  });

  test('an event with no interesting field still says something', () => {
    const odd = 'Some event\r\n\tOddKey=OddValue\r\n\tOther=Thing';
    const line = summariseEventMessage(odd);
    assert.ok(line.includes('OddKey'), 'a bare headline tells an analyst nothing');
  });

  test('a logon event surfaces the account rather than the first field', () => {
    const logon = [
      'An account was successfully logged on. EID=4624',
      '\tSubjectUserSid=S-1-5-18',
      '\tSubjectLogonId=0x3e7',
      '\tTargetUserName=oguzhan',
      '\tIpAddress=10.0.0.9',
    ].join('\r\n');
    const line = summariseEventMessage(logon);
    assert.ok(line.includes('oguzhan'), 'the account is the point of a logon event');
    assert.ok(!line.includes('S-1-5-18'), 'a SID should not win over a username');
  });

  test('never throws on anything', () => {
    for (const input of ['', undefined as any, null as any, {} as any, 0 as any]) {
      assert.equal(typeof summariseEventMessage(input), 'string');
    }
  });
});
