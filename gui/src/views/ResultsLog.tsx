import { useEffect, useState } from "react";
import { api, type LogEntry } from "../api";
import { Banner, Button, EmptyState, Pill } from "../components/ui";
import { IconRefresh, IconTrash } from "../components/icons";

function resultVariant(result: string): "ok" | "warn" | "danger" | "neutral" {
  const r = result.toLowerCase();
  if (r === "success") return "ok";
  if (r === "rejected") return "warn";
  if (r === "error") return "danger";
  return "neutral";
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function ResultsLog() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const refresh = () => api.getLog().then(setEntries).catch((e) => setError(e.message));

  useEffect(() => {
    refresh();
  }, []);

  const clear = async () => {
    setError(null);
    setClearing(true);
    try {
      await api.clearLog();
      setConfirmClear(false);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="view">
      <p className="view__intro">
        Audit trail — every action, scope check, and rejection the backend recorded, newest first.
        Clearing wipes it and leaves a single "log-cleared" marker so the reset itself is recorded.
      </p>

      <div className="toolbar">
        <Button variant="ghost" onClick={refresh} icon={<IconRefresh size={15} />}>
          Refresh
        </Button>
        {!confirmClear ? (
          <Button variant="ghost" onClick={() => setConfirmClear(true)} icon={<IconTrash size={15} />} disabled={entries.length === 0}>
            Clear log
          </Button>
        ) : (
          <>
            <Button variant="danger" onClick={clear} disabled={clearing} icon={<IconTrash size={15} />}>
              {clearing ? "Clearing…" : "Confirm clear"}
            </Button>
            <Button variant="ghost" onClick={() => setConfirmClear(false)} disabled={clearing}>
              Cancel
            </Button>
          </>
        )}
        <span className="faint">{entries.length} entries</span>
      </div>

      {error && <Banner variant="error">{error}</Banner>}

      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Target</th>
              <th>Result</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <EmptyState>No log entries yet.</EmptyState>
                </td>
              </tr>
            )}
            {entries.map((entry) => (
              <tr key={entry.id}>
                <td className="mono faint" style={{ whiteSpace: "nowrap" }}>{formatTime(entry.timestamp)}</td>
                <td className="mono">{entry.action}</td>
                <td className="mono">{entry.target ?? "—"}</td>
                <td>
                  <Pill variant={resultVariant(entry.result)} dot={false}>
                    {entry.result}
                  </Pill>
                </td>
                <td className="faint" style={{ maxWidth: 360, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={entry.detail}>
                  {entry.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
