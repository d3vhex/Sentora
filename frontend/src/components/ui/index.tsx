/**
 * The shared shell every page is built from.
 *
 * There were 1291 inline style objects across 24 pages and `StatCard` was
 * written three separate times. That is why the console looked like three
 * different products: not because any page was written carelessly, but
 * because there was no shared vocabulary to be careless *about*. Spacing,
 * radius and colour were decided again on every page, and diverged the way
 * independently made decisions always do.
 *
 * These primitives are deliberately small and unclever. They read tokens from
 * index.css and expose almost no styling props, because a component that
 * takes `padding` is a component that will be given a different padding on
 * every page and we are back where we started.
 *
 * Responsiveness lives here rather than in each page. A page that lays itself
 * out cannot be made responsive twenty times.
 */
import React from 'react';
import { AlertTriangle, Inbox, Loader2 } from 'lucide-react';

/* ── Page shell ─────────────────────────────────────────────────────────── */

export function PageHeader({
  title, subtitle, icon, actions,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <header
      style={{
        display: 'flex', flexWrap: 'wrap', gap: 'var(--space-4)',
        alignItems: 'flex-start', justifyContent: 'space-between',
        marginBottom: 'var(--space-6)',
        paddingBottom: 'var(--space-4)',
        borderBottom: '1px solid var(--border-color)',
      }}
    >
      <div style={{ minWidth: 0 }}>
        <h1
          style={{
            display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
            fontSize: 'var(--text-2xl)', fontWeight: 500, margin: 0,
          }}
        >
          {icon}
          {title}
        </h1>
        {subtitle && (
          <p
            style={{
              margin: 'var(--space-2) 0 0', color: 'var(--text-secondary)',
              fontSize: 'var(--text-sm)', maxWidth: '68ch',
            }}
          >
            {subtitle}
          </p>
        )}
      </div>
      {actions && (
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          {actions}
        </div>
      )}
    </header>
  );
}

export function Card({
  children, title, actions, interactive, onClick, style,
}: {
  children: React.ReactNode;
  title?: React.ReactNode;
  actions?: React.ReactNode;
  interactive?: boolean;
  onClick?: () => void;
  style?: React.CSSProperties;
}) {
  return (
    <section
      className={interactive ? 'card card--interactive' : 'card'}
      onClick={onClick}
      style={style}
    >
      {(title || actions) && (
        <div
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            gap: 'var(--space-3)', marginBottom: 'var(--space-4)',
          }}
        >
          {title && (
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 500, margin: 0 }}>
              {title}
            </h2>
          )}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/** One number and what it means.
 *
 * `sub` is not optional decoration. A figure on a security console without a
 * sentence saying what it counts is how "23" comes to mean three different
 * things on three pages. */
export function StatCard({
  label, value, sub, color, icon,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  color?: string;
  icon?: React.ReactNode;
}) {
  return (
    <div className="card" style={{ padding: 'var(--space-4)' }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
          color: 'var(--text-secondary)', fontSize: 'var(--text-xs)',
          textTransform: 'uppercase', letterSpacing: '0.04em',
        }}
      >
        {icon}
        {label}
      </div>
      <div
        style={{
          fontSize: 'var(--text-3xl)', fontWeight: 500, lineHeight: 1.15,
          margin: 'var(--space-2) 0 0', color: color || 'var(--text-primary)',
        }}
      >
        {value}
      </div>
      {sub && (
        <div
          style={{
            marginTop: 'var(--space-1)', color: 'var(--text-muted)',
            fontSize: 'var(--text-xs)',
          }}
        >
          {sub}
        </div>
      )}
    </div>
  );
}

/* ── States a page is in before it has data ─────────────────────────────── */

/**
 * The three of these exist together on purpose.
 *
 * "Loading", "nothing here" and "this failed" were routinely collapsed into
 * one blank area, and on a security console that is the worst possible
 * ambiguity: an empty alert list and an alert list that failed to load look
 * identical, and only one of them means you are safe.
 */
export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div style={stateBox}>
      <Loader2 size={18} className="spin" style={{ color: 'var(--text-muted)' }} />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({
  title, detail, icon,
}: { title: string; detail?: string; icon?: React.ReactNode }) {
  return (
    <div style={stateBox}>
      {icon ?? <Inbox size={18} style={{ color: 'var(--text-muted)' }} />}
      <div>
        <div style={{ color: 'var(--text-secondary)' }}>{title}</div>
        {detail && (
          <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
            {detail}
          </div>
        )}
      </div>
    </div>
  );
}

/** Never silently. A page that failed to load must say so and say why. */
export function ErrorState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div
      style={{
        ...stateBox,
        borderColor: 'rgba(220,91,91,0.3)',
        background: 'rgba(220,91,91,0.05)',
      }}
    >
      <AlertTriangle size={18} style={{ color: 'var(--accent-color)' }} />
      <div>
        <div style={{ color: 'var(--text-primary)' }}>{title}</div>
        {detail && (
          <div style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>
            {detail}
          </div>
        )}
      </div>
    </div>
  );
}

const stateBox: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
  padding: 'var(--space-5)',
  border: '1px dashed var(--border-color)',
  borderRadius: 'var(--radius-md)',
  color: 'var(--text-secondary)',
  fontSize: 'var(--text-sm)',
};

/* ── Small pieces ───────────────────────────────────────────────────────── */

export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'ok' | 'neutral';

const TONE_COLOR: Record<Tone, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
  ok: 'var(--accent-success)',
  neutral: 'var(--accent-neutral)',
};

export function toneColor(tone: Tone): string {
  return TONE_COLOR[tone] ?? TONE_COLOR.neutral;
}

/** Severity as a label, so no page has to decide which red is critical. */
export function Badge({
  children, tone = 'neutral',
}: { children: React.ReactNode; tone?: Tone }) {
  const color = toneColor(tone);
  return (
    <span
      style={{
        display: 'inline-flex', alignItems: 'center',
        padding: '1px var(--space-2)',
        border: `1px solid ${color}`,
        borderRadius: 'var(--radius-sm)',
        color,
        fontSize: 'var(--text-xs)',
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  );
}

/** A table that scrolls sideways rather than breaking the page.
 *
 * Wide content is the one thing that makes a console unusable on a laptop:
 * the body scrolls horizontally, the sidebar drifts, and every column is a
 * pixel too narrow. The overflow belongs to the table, not to the page. */
export function DataTable({
  columns, children,
}: { columns: React.ReactNode[]; children: React.ReactNode }) {
  return (
    <div className="table-responsive">
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
        <thead>
          <tr>
            {columns.map((c, i) => (
              <th
                key={i}
                style={{
                  textAlign: 'left', padding: 'var(--space-2) var(--space-3)',
                  borderBottom: '1px solid var(--border-color)',
                  color: 'var(--text-muted)', fontWeight: 500,
                  fontSize: 'var(--text-xs)', textTransform: 'uppercase',
                  letterSpacing: '0.04em', whiteSpace: 'nowrap',
                }}
              >
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Row({ children }: { children: React.ReactNode }) {
  return <tr style={{ borderBottom: '1px solid var(--border-color)' }}>{children}</tr>;
}

export function Cell({
  children, mono, align,
}: { children: React.ReactNode; mono?: boolean; align?: 'left' | 'right' }) {
  return (
    <td
      className={mono ? 'mono' : undefined}
      style={{
        padding: 'var(--space-2) var(--space-3)',
        textAlign: align ?? 'left',
        color: 'var(--text-secondary)',
        verticalAlign: 'top',
      }}
    >
      {children}
    </td>
  );
}
