import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';

/**
 * An interactive shell on the endpoint.
 *
 * The screen stream is the wrong tool for the machines that matter: a
 * headless server has no desktop and never will, and the agent now says so
 * rather than showing a black rectangle. What an operator wanted from it was
 * a console.
 *
 * xterm.js rather than a `<pre>`: a real shell emits ANSI escapes for colour,
 * cursor movement and full-screen programs, and rendering those as text looks
 * broken in a way that reads as "the console is broken".
 *
 * Frames are JSON both ways - see `Sentora/modules/console`:
 *   out  {t:'i', d:'ls\n'}  keystrokes      {t:'r', cols, rows}  resize
 *   in   {t:'o', d:'...'}   output
 *        {t:'x', code, why} the session ended
 *        {t:'e', d:'...'}   it could not start
 */

interface Props {
  agentName: string;
}

const AgentConsole: React.FC<Props> = ({ agentName }) => {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [status, setStatus] = useState('Connecting…');
  const [ended, setEnded] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [note, setNote] = useState('');
  // A ref, not state: `onData` closes over this and must see the current
  // value without the handler being torn down and rebuilt on every change.
  const modeRef = useRef<'pty' | 'pipe'>('pty');
  // The line being typed, in pipe mode. Held here rather than in state so a
  // keystroke does not re-render the component, and so the handler always
  // reads the current value rather than the one it closed over.
  const lineRef = useRef('');
  // The pending "draw the prompt" timer, and the function that arms it.
  // `ws.onmessage` is defined before `schedulePrompt` exists, so it reaches it
  // through a ref rather than the two being reordered - the message handler
  // has to be attached before the socket can open.
  const promptTimer = useRef<number | null>(null);
  const schedulePromptRef = useRef<((quietMs: number) => void) | null>(null);

  useEffect(() => {
    if (!hostRef.current || !agentName) return;

    const term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontFamily: '"Source Code Pro", ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      scrollback: 5000,
      theme: { background: '#0b0d12', foreground: '#d8dee9', cursor: '#8fbcbb' },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    try { fit.fit(); } catch { /* the container may not be laid out yet */ }
    termRef.current = term;
    fitRef.current = fit;

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${protocol}://${window.location.host}/console-proxy/${agentName}`);
    wsRef.current = ws;
    setEnded(false);

    const send = (payload: object) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
    };

    ws.onopen = () => {
      setStatus('Connected');
      send({ t: 'r', cols: term.cols, rows: term.rows });
      term.focus();
    };

    ws.onmessage = (ev) => {
      let msg: any;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.t === 'm') {
        // What kind of session this is, before the first keystroke. A
        // pipe-backed shell renders nothing as you type and hangs on `vim`;
        // shown without saying so it reads as a broken terminal.
        modeRef.current = msg.mode === 'pipe' ? 'pipe' : 'pty';
        setNote(msg.note || '');
        if (modeRef.current === 'pipe') {
          // The shell draws no prompt in this mode - that is what stops it
          // echoing every line twice - so the terminal draws its own.
          lineRef.current = '';
          term.write('\x1b[36m>\x1b[0m ');
        }
        return;
      }
      if (msg.t === 'o') {
        term.write(msg.d);
        // Output is still arriving, so push the prompt back. A long command
        // keeps deferring it until it goes quiet.
        if (modeRef.current === 'pipe' && promptTimer.current !== null) {
          schedulePromptRef.current?.(250);
        }
      } else if (msg.t === 'x') {
        // The shell ended. Say why, and stop pretending the session is live -
        // a terminal that silently stops accepting input is the confusing
        // version of this.
        setEnded(true);
        setStatus(msg.why ? `Session ended: ${msg.why}` : 'Session ended');
        term.write(`\r\n\x1b[33m── session ended${msg.why ? `: ${msg.why}` : ''} ──\x1b[0m\r\n`);
      } else if (msg.t === 'e') {
        setEnded(true);
        setStatus(`Agent: ${msg.d}`);
        term.write(`\r\n\x1b[31m${msg.d}\x1b[0m\r\n`);
      }
    };

    ws.onerror = () => { if (!ended) setStatus('Error'); };
    ws.onclose = () => {
      // Do not overwrite a reason the agent already gave: the close event
      // arrives right after it and would replace the one useful sentence with
      // "Disconnected".
      setEnded(true);
      setStatus((s) => (s.startsWith('Session ended') || s.startsWith('Agent:') ? s : 'Disconnected'));
    };

    /** Draw the prompt, on a line of its own.
     *
     *  Output usually ends with a newline and sometimes does not, so this
     *  asks the terminal where the cursor is rather than guessing - adding an
     *  unconditional newline left a blank line after every command. */
    const writePrompt = () => {
      if (term.buffer.active.cursorX > 0) term.write('\r\n');
      term.write('\x1b[36m>\x1b[0m ');
    };

    /** Draw it once the output has stopped arriving.
     *
     *  Drawing it straight after Enter put it *above* the output of the
     *  command that had just been sent, so the transcript read as though
     *  every result belonged to the next prompt. There is no way to know a
     *  command has finished - a pipe carries no such signal - so quiet is the
     *  best available proxy: each chunk of output pushes it back, and a
     *  command that prints nothing still gets its prompt. */
    const schedulePrompt = (quietMs: number) => {
      if (promptTimer.current !== null) window.clearTimeout(promptTimer.current);
      promptTimer.current = window.setTimeout(() => {
        promptTimer.current = null;
        writePrompt();
      }, quietMs);
    };
    schedulePromptRef.current = schedulePrompt;

    const onData = term.onData((data) => {
      // A real terminal does its own line discipline: the pty echoes, handles
      // backspace, and hands the shell a finished line. Keystrokes go
      // straight through.
      if (modeRef.current !== 'pipe') {
        send({ t: 'i', d: data });
        return;
      }

      // A pipe has none of that, so the line is edited here and sent whole.
      // Sending keystrokes one at a time meant backspace travelled to the
      // shell as a character *inside the command*, so anything the operator
      // corrected still ran - and with the shell echoing as well, one
      // keypress appeared two or three times.
      for (const ch of data) {
        if (ch === '\r' || ch === '\n') {
          term.write('\r\n');
          send({ t: 'i', d: lineRef.current + '\n' });
          lineRef.current = '';
          // Nothing may come back at all, so this is a floor rather than a
          // guess at how long the command takes; output pushes it later.
          schedulePrompt(500);
        } else if (ch === '\x7f' || ch === '\b') {
          if (lineRef.current) {
            lineRef.current = lineRef.current.slice(0, -1);
            term.write('\b \b');
          }
        } else if (ch === '\x03') {
          // Ctrl+C cannot be signalled down a pipe. Abandon the line rather
          // than send a control character the shell would try to run.
          term.write('^C\r\n');
          lineRef.current = '';
          // Nothing may come back at all, so this is a floor rather than a
          // guess at how long the command takes; output pushes it later.
          schedulePrompt(500);
        } else if (ch >= ' ') {
          lineRef.current += ch;
          term.write(ch);
        }
      }
    });

    const onResize = () => {
      try { fit.fit(); } catch { /* ignore */ }
      send({ t: 'r', cols: term.cols, rows: term.rows });
    };
    window.addEventListener('resize', onResize);

    // The container also changes size when the sidebar collapses, which no
    // window resize event reports.
    const observer = new ResizeObserver(onResize);
    observer.observe(hostRef.current);

    return () => {
      window.removeEventListener('resize', onResize);
      observer.disconnect();
      onData.dispose();
      if (promptTimer.current !== null) window.clearTimeout(promptTimer.current);
      promptTimer.current = null;
      schedulePromptRef.current = null;
      try { ws.close(); } catch { /* ignore */ }
      term.dispose();
      termRef.current = null;
      wsRef.current = null;
    };
  }, [agentName, attempt]);

  const live = status === 'Connected';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '12px 16px', borderBottom: '1px solid var(--border-color)',
        gap: '12px', flexWrap: 'wrap',
      }}>
        <div style={{ fontWeight: 700 }}>Console</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{
            fontSize: '0.75rem', fontWeight: 700, padding: '4px 10px', borderRadius: '20px',
            color: live ? 'var(--accent-success)' : 'var(--accent-color)',
            backgroundColor: live ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
          }}>
            {status}
          </span>
          {ended && (
            <button
              onClick={() => setAttempt((n) => n + 1)}
              style={{
                padding: '4px 12px', borderRadius: '6px', fontSize: '0.75rem',
                border: '1px solid var(--border-color)', color: 'var(--text-primary)',
                cursor: 'pointer', backgroundColor: 'transparent',
              }}>
              Reconnect
            </button>
          )}
        </div>
      </div>

      {note && (
        <div style={{
          padding: '8px 16px', fontSize: '0.75rem',
          color: 'var(--accent-warning)',
          backgroundColor: 'rgba(234,179,8,0.08)',
          borderBottom: '1px solid var(--border-color)',
        }}>
          {note}
        </div>
      )}

      <div ref={hostRef} style={{ flex: 1, minHeight: 0, padding: '8px', backgroundColor: '#0b0d12' }} />

      <div style={{
        padding: '8px 16px', borderTop: '1px solid var(--border-color)',
        fontSize: '0.6875rem', color: 'var(--text-secondary)',
      }}>
        This is a shell as the user the agent runs as — root on Linux, SYSTEM on
        Windows. Every session is recorded in the audit log. It closes itself
        after 15 minutes idle, or an hour open.
      </div>
    </div>
  );
};

export default AgentConsole;
