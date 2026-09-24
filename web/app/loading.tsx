export default function Loading() {
  return (
    <div className="page">
      <div className="state-page" role="status" aria-live="polite">
        <span className="eyebrow">Loading</span>
        <span className="sk sk-l" />
        <span className="sk sk-m" />
      </div>
    </div>
  );
}
