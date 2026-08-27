import React, { useEffect, useRef, useState } from 'react';
import { MonitorOff } from 'lucide-react';

interface VncViewerProps {
  agentName: string;
}

const VncViewer: React.FC<VncViewerProps> = ({ agentName }) => {
  const imgRef = useRef<HTMLImageElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const lastUrlRef = useRef<string | null>(null);
  const [status, setStatus] = useState<string>('Connecting...');
  const [fps, setFps] = useState<number>(10);
  const [quality, setQuality] = useState<number>(60);
  // Whether a frame has ever arrived. Drives the placeholder below, because
  // an <img> with no src paints a broken-image icon.
  const [hasFrame, setHasFrame] = useState<boolean>(false);

  useEffect(() => {
    if (!agentName) return;
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host = window.location.host;
    const wsUrl = `${protocol}://${host}/vnc-proxy/${agentName}?fps=${fps}&q=${quality}&w=1280`;

    setStatus('Connecting...');
    setHasFrame(false);
    let frameCount = 0;
    let lastFpsCheck = Date.now();

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    ws.binaryType = 'blob';

    ws.onopen = () => setStatus('Connected');
    ws.onerror = () => setStatus('Error');
    ws.onclose = (e) => setStatus(e.reason ? `Closed: ${e.reason}` : 'Closed');

    ws.onmessage = (ev) => {
      // Server can send JSON error frames as text; image frames are blobs.
      if (typeof ev.data === 'string') {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.error) setStatus(`Agent: ${msg.error}`);
        } catch {
          /* ignore */
        }
        return;
      }
      const url = URL.createObjectURL(ev.data as Blob);
      // Revoke the previous frame's URL to keep memory bounded — the browser
      // would otherwise hold every JPEG we ever displayed.
      if (lastUrlRef.current) URL.revokeObjectURL(lastUrlRef.current);
      lastUrlRef.current = url;
      if (imgRef.current) imgRef.current.src = url;
      setHasFrame(true);

      frameCount += 1;
      const now = Date.now();
      if (now - lastFpsCheck > 2000) {
        const realFps = (frameCount * 1000) / (now - lastFpsCheck);
        setStatus(`Streaming · ${realFps.toFixed(1)} fps`);
        frameCount = 0;
        lastFpsCheck = now;
      }
    };

    return () => {
      try { ws.close(); } catch { /* ignore */ }
      if (lastUrlRef.current) URL.revokeObjectURL(lastUrlRef.current);
      lastUrlRef.current = null;
    };
  }, [agentName, fps, quality]);

  const isLive = status.startsWith('Connected') || status.startsWith('Streaming');
  const isErr = status.startsWith('Error') || status.startsWith('Closed') || status.startsWith('Agent:');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: '12px 20px', backgroundColor: 'var(--card-bg)', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        <h3 style={{ fontSize: '1.125rem' }}>Remote Desktop</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            FPS
            <select value={fps} onChange={e => setFps(parseInt(e.target.value))}
              style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '4px 8px', color: 'var(--text-primary)' }}>
              {[5, 10, 15, 20, 30].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            Quality
            <select value={quality} onChange={e => setQuality(parseInt(e.target.value))}
              style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '4px 8px', color: 'var(--text-primary)' }}>
              {[30, 50, 60, 75, 90].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <span style={{
            fontSize: '0.75rem',
            fontWeight: 600,
            color: isLive ? 'var(--accent-success)' : isErr ? 'var(--accent-color)' : 'var(--text-secondary)',
            backgroundColor: 'rgba(255,255,255,0.05)',
            padding: '4px 10px',
            borderRadius: '12px',
          }}>
            {status}
          </span>
        </div>
      </div>
      <div style={{ flex: 1, backgroundColor: '#000', minHeight: '600px', display: 'flex', justifyContent: 'center', alignItems: 'center', overflow: 'hidden', padding: '24px' }}>
        {/* The <img> is mounted only once a frame has arrived. An <img> with
            no src renders as a broken-image icon, which is what a headless
            server used to show beside a green "Connected" chip - a broken
            feature, rather than a machine with no screen. */}
        <img
          ref={imgRef}
          alt=""
          style={{
            maxWidth: '100%', maxHeight: '100%',
            display: hasFrame ? 'block' : 'none',
          }}
        />
        {!hasFrame && (
          <div style={{ textAlign: 'center', maxWidth: '52ch', color: 'var(--text-secondary)' }}>
            <MonitorOff size={40} style={{ opacity: 0.5, marginBottom: '14px' }} />
            <div style={{ fontSize: '0.9375rem', color: 'var(--text-primary)', marginBottom: '8px' }}>
              {isErr ? 'No screen to show' : 'Waiting for the first frame…'}
            </div>
            <div style={{ fontSize: '0.8125rem', lineHeight: 1.6 }}>
              {isErr
                ? status.replace(/^Agent:\s*/, '')
                : 'If nothing appears, the host may have no display — a headless server has no screen to stream.'}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default VncViewer;
