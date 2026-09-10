/**
 * Read the databases directly, when the pages built on top of them disagree.
 *
 * Both loaders here dropped their errors on the floor - `getDatabases()` had a
 * `.finally` and no `.catch`, so a failed request left an empty sidebar and an
 * unhandled rejection in the browser console. On a page whose whole purpose is
 * "what is actually in there", a list that is empty because the request failed
 * is worse than no page at all: it answers the question wrongly.
 *
 * The two destructive actions were `window.confirm`. They are dialogs now,
 * which lets them say what is about to happen and to what.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { Database, Table, RefreshCw, AlertTriangle, List, Grid, Trash2 } from 'lucide-react';
import { adminService } from '../services/api';
import {
  PageHeader, Card, DataTable, Row, Cell,
  EmptyState, ErrorState, LoadingState, Modal, DialogButton,
} from '../components/ui';

type Column = {
  name: string; type: string; null: string;
  key?: string; default?: string; extra?: string;
};

const Databases: React.FC = () => {
  const [databases, setDatabases] = useState<string[]>([]);
  const [selectedDb, setSelectedDb] = useState('');
  const [tables, setTables] = useState<string[]>([]);
  const [selectedTable, setSelectedTable] = useState('');
  const [columns, setColumns] = useState<Column[]>([]);
  const [tableData, setTableData] = useState<Record<string, unknown>[]>([]);
  const [viewMode, setViewMode] = useState<'tables' | 'columns' | 'data'>('tables');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmDrop, setConfirmDrop] = useState(false);
  const [confirmClear, setConfirmClear] = useState<string | null>(null);

  const say = (err: any, fallback: string) =>
    err?.response?.data?.message || err?.message || fallback;

  const fetchDbs = useCallback(async () => {
    setLoading(true);
    try {
      const list = await adminService.getDatabases();
      setDatabases(list);
      setError(null);
      setSelectedDb((current) => current || list[0] || '');
    } catch (err) {
      setError(say(err, 'Could not list databases'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchDbs(); }, [fetchDbs]);

  useEffect(() => {
    if (!selectedDb) return;
    let cancelled = false;
    setLoading(true);
    adminService.getDatabaseTables(selectedDb)
      .then((list) => {
        if (cancelled) return;
        setTables(list);
        setSelectedTable('');
        setViewMode('tables');
        setError(null);
      })
      .catch((err) => { if (!cancelled) setError(say(err, `Could not list tables in ${selectedDb}`)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [selectedDb]);

  const handleInspectTable = async (table: string) => {
    setSelectedTable(table);
    setLoading(true);
    try {
      const [cols, data] = await Promise.all([
        adminService.getTableColumns(selectedDb, table),
        adminService.getTableData(selectedDb, table),
      ]);
      setColumns(cols);
      setTableData(data);
      setViewMode('data');
      setError(null);
    } catch (err) {
      // Cleared rather than left stale. Showing the previous table's rows under
      // this table's name is the one outcome worse than showing nothing.
      setColumns([]);
      setTableData([]);
      setError(say(err, `Could not read ${table}`));
    } finally {
      setLoading(false);
    }
  };

  const handleDropDb = async () => {
    setConfirmDrop(false);
    try {
      await adminService.dropDatabase(selectedDb);
      setSelectedDb('');
      setTables([]);
      setSelectedTable('');
      fetchDbs();
    } catch (err) {
      setError(say(err, `Could not drop ${selectedDb}`));
    }
  };

  const handleClearTable = async (table: string) => {
    setConfirmClear(null);
    try {
      await adminService.clearTable(selectedDb.replace('_db', ''), table);
      if (selectedTable === table) handleInspectTable(table);
    } catch (err) {
      setError(say(err, `Could not clear ${table}. Only agent databases support clear.`));
    }
  };

  const sideList = (
    items: string[],
    active: string,
    onPick: (v: string) => void,
    Icon: typeof Database,
    emptyText: string,
  ) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
      {items.length === 0 && (
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
          {emptyText}
        </span>
      )}
      {items.map((item) => {
        const on = active === item;
        return (
          <button
            key={item}
            onClick={() => onPick(item)}
            style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
              padding: 'var(--space-2)', textAlign: 'left',
              border: '1px solid transparent',
              borderRadius: 'var(--radius-md)',
              fontSize: 'var(--text-sm)',
              cursor: 'pointer',
              background: on ? 'var(--bg-color)' : 'transparent',
              borderColor: on ? 'var(--border-color)' : 'transparent',
              color: on ? 'var(--text-primary)' : 'var(--text-secondary)',
            }}
          >
            <Icon size={15} />
            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {item}
            </span>
          </button>
        );
      })}
    </div>
  );

  const tablesPanel = () => (
    <div>
      <EmptyState
        title={selectedDb}
        detail={`${tables.length} table${tables.length === 1 ? '' : 's'}. Select one on the left to read its structure and rows.`}
        icon={<Table size={18} style={{ color: 'var(--text-muted)' }} />}
      />
      {selectedDb !== 'userdb' && (
        <button
          className="btn-secondary"
          onClick={() => setConfirmDrop(true)}
          style={{ marginTop: 'var(--space-4)', color: 'var(--accent-color)' }}
        >
          <Trash2 size={15} /> Drop database
        </button>
      )}
    </div>
  );

  const columnsPanel = () => {
    if (columns.length === 0) {
      return <EmptyState title="No columns" detail={`${selectedTable} reported no schema.`} />;
    }
    return (
      <DataTable columns={['Column', 'Type', 'Null', 'Key', 'Default', 'Extra']}>
        {columns.map((col) => (
          <Row key={col.name}>
            <Cell>{col.name}</Cell>
            <Cell mono>{col.type}</Cell>
            <Cell>{col.null}</Cell>
            <Cell>{col.key || '—'}</Cell>
            <Cell mono>{col.default ?? 'NULL'}</Cell>
            <Cell>{col.extra || '—'}</Cell>
          </Row>
        ))}
      </DataTable>
    );
  };

  const rowsPanel = () => (
    <div>
      <div
        style={{
          display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', gap: 'var(--space-3)',
          marginBottom: 'var(--space-4)',
        }}
      >
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {selectedTable} — first 100 rows
        </span>
        <button
          className="btn-secondary"
          onClick={() => setConfirmClear(selectedTable)}
          style={{ color: 'var(--accent-color)' }}
        >
          <Trash2 size={14} /> Clear table
        </button>
      </div>
      {tableData.length === 0 ? (
        <EmptyState
          title="No rows"
          detail={`${selectedTable} exists and is empty. If you expected rows, the telemetry health page says where they stopped.`}
        />
      ) : (
        <DataTable columns={columns.map((c) => c.name)}>
          {tableData.map((row, i) => (
            <Row key={`row-${i}`}>
              {columns.map((col) => {
                const text = row[col.name]?.toString() ?? 'NULL';
                return (
                  <Cell key={col.name} mono>
                    <span
                      style={{
                        display: 'inline-block', maxWidth: 300,
                        overflow: 'hidden', textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap', verticalAlign: 'bottom',
                      }}
                      title={text}
                    >
                      {text}
                    </span>
                  </Cell>
                );
              })}
            </Row>
          ))}
        </DataTable>
      )}
    </div>
  );

  /** The main panel, by view mode. It was a four-way nested ternary inside the
   *  JSX, which is how `viewMode === 'columns'` came to hide a second ternary
   *  inside itself. */
  const panel = () => {
    if (loading) return <LoadingState />;
    if (!selectedDb) {
      return (
        <EmptyState
          title="No database selected"
          detail="Pick one on the left to see its tables."
          icon={<Database size={18} style={{ color: 'var(--text-muted)' }} />}
        />
      );
    }
    if (viewMode === 'tables') return tablesPanel();
    if (viewMode === 'columns') return columnsPanel();
    return rowsPanel();
  };

  return (
    <div>
      <PageHeader
        title="Database Explorer"
        subtitle="Schema, columns and rows as they actually are, for when a page and its data disagree."
        icon={<Database size={22} />}
        actions={
          <>
            {selectedTable && (
              <>
                <button
                  className={viewMode === 'columns' ? 'btn-primary' : 'btn-secondary'}
                  onClick={() => setViewMode('columns')}
                >
                  <List size={15} /> Columns
                </button>
                <button
                  className={viewMode === 'data' ? 'btn-primary' : 'btn-secondary'}
                  onClick={() => setViewMode('data')}
                >
                  <Grid size={15} /> Rows
                </button>
              </>
            )}
            <button className="btn-secondary" onClick={fetchDbs}>
              <RefreshCw size={15} /> Refresh
            </button>
          </>
        }
      />

      {error && <ErrorState title="Database request failed" detail={error} />}

      <div
        style={{
          display: 'grid', gap: 'var(--space-5)',
          gridTemplateColumns: 'minmax(200px, 260px) 1fr',
          alignItems: 'start', marginTop: error ? 'var(--space-5)' : 0,
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <Card title="Databases">
            {loading && databases.length === 0
              ? <LoadingState label="Listing…" />
              : sideList(databases, selectedDb, setSelectedDb, Database, 'None returned.')}
          </Card>
          <Card title={selectedDb ? `Tables in ${selectedDb}` : 'Tables'}>
            {sideList(tables, selectedTable, handleInspectTable, Table,
              selectedDb ? 'This database has no tables.' : 'Pick a database first.')}
          </Card>
        </div>

        <Card>{panel()}</Card>
      </div>

      <div style={{ marginTop: 'var(--space-5)' }}>
        <ErrorState
          title="This is live data"
          detail="Clear and Drop take effect immediately and cannot be undone. Nothing here is a copy."
        />
      </div>

      {confirmDrop && (
        <Modal
          title={`Drop ${selectedDb}?`}
          subtitle="Every table in it and everything they hold. This cannot be undone and there is no copy."
          onClose={() => setConfirmDrop(false)}
          footer={
            <>
              <DialogButton onClick={() => setConfirmDrop(false)}>Cancel</DialogButton>
              <DialogButton variant="solid" tone="critical" onClick={handleDropDb}>
                Drop database
              </DialogButton>
            </>
          }
        >
          <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
            <AlertTriangle size={18} style={{ color: 'var(--accent-color)', flexShrink: 0 }} />
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              If this is an agent's database, the agent still believes the server holds
              what it has already sent, and will not offer those rows again until it
              notices the reset.
            </p>
          </div>
        </Modal>
      )}

      {confirmClear && (
        <Modal
          title={`Clear ${confirmClear}?`}
          subtitle="Deletes every row. The table itself stays."
          onClose={() => setConfirmClear(null)}
          footer={
            <>
              <DialogButton onClick={() => setConfirmClear(null)}>Cancel</DialogButton>
              <DialogButton
                variant="solid"
                tone="critical"
                onClick={() => handleClearTable(confirmClear)}
              >
                Clear table
              </DialogButton>
            </>
          }
        >
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Only agent databases support this.
          </p>
        </Modal>
      )}
    </div>
  );
};

export default Databases;
