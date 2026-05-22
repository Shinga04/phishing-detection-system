function formatAccuracy(value) {
  if (value == null || Number.isNaN(Number(value))) return "—";
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function formatTime(iso) {
  if (!iso) return "Never";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function LearningStats({ stats, onRetrain, retrainLoading }) {
  if (!stats) return null;

  return (
    <section className="card learning-stats">
      <h2>Adaptive Learning</h2>
      <div className="stats-grid">
        <div className="stat-tile">
          <span className="stat-label">Samples learned</span>
          <span className="stat-value">{stats.total_samples_learned ?? 0}</span>
        </div>
        <div className="stat-tile">
          <span className="stat-label">New threats collected</span>
          <span className="stat-value">{stats.new_threats_collected ?? 0}</span>
        </div>
        <div className="stat-tile">
          <span className="stat-label">Model accuracy (CV)</span>
          <span className="stat-value">{formatAccuracy(stats.model_accuracy)}</span>
        </div>
        <div className="stat-tile">
          <span className="stat-label">Last retraining</span>
          <span className="stat-value stat-value--small">{formatTime(stats.last_retrain_time)}</span>
        </div>
      </div>
      <p className="learning-hint">
        Uncertain scans and your feedback are saved locally. Retrain merges them with the original dataset.
      </p>
      <button
        type="button"
        className="btn secondary"
        disabled={retrainLoading}
        onClick={onRetrain}
      >
        {retrainLoading ? "Retraining…" : "Retrain model now"}
      </button>
    </section>
  );
}

export default LearningStats;
