
export function ActivityPage(props: { history: string; onLoad: () => Promise<void> }) {
  return (
    <div className="stack">
      <div className="card">
        <h2 className="section-title">Activity</h2>
        <div className="toolbar">
          <button onClick={props.onLoad}>Load history</button>
        </div>
        <pre>{props.history || "No activity loaded yet."}</pre>
      </div>
    </div>
  );
}
