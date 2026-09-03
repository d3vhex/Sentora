/**
 * Charts that look like the rest of the console.
 *
 * Recharts styles itself with props, not CSS, so left alone it draws a white
 * grid, a blue line and a light tooltip on a black page. These wrappers read
 * the same tokens everything else does, which is the only way the theme
 * survives contact with a charting library.
 *
 * Three rules the wrappers enforce rather than leaving to each call site:
 *
 * Series colours come from `--chart-*` and never from `--sev-*`. A bar being
 * red should not imply danger unless danger is what the bar measures.
 *
 * Axes and grid are quiet. On a data page the reader is looking at the shape;
 * a grid that competes with the series is a grid that has to be looked past.
 *
 * A chart with no data says so. An empty chart and a chart that failed to
 * load are the same picture, and on a security console the difference is
 * whether you are safe or blind.
 */
import React from 'react';
import {
  Bar, BarChart, CartesianGrid, Cell, ComposedChart, Legend, Line,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import { EmptyState } from './index';

/** Read a CSS custom property, so the palette has one home. */
const token = (name: string, fallback: string) => {
  if (typeof window === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(name).trim();
  return value || fallback;
};

export const SERIES = [
  'var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)',
  'var(--chart-4)', 'var(--chart-5)', 'var(--chart-6)',
];

const axis = {
  stroke: 'var(--chart-axis)',
  fontSize: 11,
  tickLine: false,
} as const;

const tooltipStyle = {
  contentStyle: {
    background: 'var(--surface-2)',
    border: '1px solid var(--border-strong)',
    borderRadius: 'var(--radius-md)',
    fontSize: '0.8125rem',
    color: 'var(--text-primary)',
  },
  labelStyle: { color: 'var(--text-secondary)' },
  cursor: { fill: 'rgba(255,255,255,0.03)' },
} as const;

function Frame({
  height = 220, empty, children,
}: { height?: number; empty: boolean; children: React.ReactElement }) {
  if (empty) {
    return (
      <EmptyState
        title="Nothing to plot yet"
        detail="No data in this window — which is a real answer, not a loading state."
      />
    );
  }
  return (
    <div style={{ width: '100%', height }}>
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}

/** A count per category. The workhorse. */
export function CategoryBars({
  data, height, colorFor,
}: {
  data: { name: string; value: number }[];
  height?: number;
  /** Per-bar colour, for the charts where the category *is* a severity. */
  colorFor?: (row: { name: string; value: number }, index: number) => string;
}) {
  return (
    <Frame height={height} empty={!data.some((d) => d.value > 0)}>
      <BarChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis dataKey="name" {...axis} interval={0} angle={-12} textAnchor="end" height={48} />
        <YAxis {...axis} allowDecimals={false} />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="value" radius={[2, 2, 0, 0]} maxBarSize={56}>
          {data.map((row, i) => (
            <Cell key={row.name}
                  fill={colorFor ? colorFor(row, i) : SERIES[i % SERIES.length]} />
          ))}
        </Bar>
      </BarChart>
    </Frame>
  );
}

/** Two counts a day, on two axes, because their shapes mean different things.
 *
 * A spike in detections with a flat distinct line is almost always one noisy
 * rule rather than an incident, and that is only visible when both are drawn
 * together. */
export function TrendChart({
  data, height,
}: {
  data: { date: string; detections: number; distinct: number }[];
  height?: number;
}) {
  const short = (d: string) => d.slice(5);   // MM-DD
  return (
    <Frame height={height ?? 260} empty={!data.some((d) => d.detections > 0)}>
      <ComposedChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis dataKey="date" tickFormatter={short} {...axis} />
        <YAxis yAxisId="left" {...axis} allowDecimals={false} />
        <YAxis yAxisId="right" orientation="right" {...axis} allowDecimals={false} />
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }} />
        <Bar yAxisId="left" dataKey="detections" name="Detections"
             fill="var(--chart-1)" radius={[2, 2, 0, 0]} maxBarSize={28} />
        <Line yAxisId="right" dataKey="distinct" name="Distinct techniques"
              stroke="var(--chart-2)" strokeWidth={2} dot={false} />
      </ComposedChart>
    </Frame>
  );
}

/** A share of a whole. Used sparingly: a donut answers "what proportion",
 *  and almost every other question on this console is better as bars. */
export function ShareDonut({
  data, height,
}: { data: { name: string; value: number }[]; height?: number }) {
  return (
    <Frame height={height ?? 220} empty={!data.some((d) => d.value > 0)}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name"
             innerRadius="55%" outerRadius="80%" paddingAngle={2}
             stroke={token('--bg-color', '#000')}>
          {data.map((row, i) => (
            <Cell key={row.name} fill={SERIES[i % SERIES.length]} />
          ))}
        </Pie>
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }} />
      </PieChart>
    </Frame>
  );
}
