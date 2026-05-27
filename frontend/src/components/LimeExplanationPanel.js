import {
  getExplanationIntro,
  groupByCategory,
  normalizeExplanationItems,
  resolveScanType,
} from "../config/limeExplanationConfig";

function polarityClass(polarity) {
  if (polarity === "elevated_risk") return "explain-impact explain-impact--risk";
  if (polarity === "legitimacy_support") return "explain-impact explain-impact--safe";
  if (polarity === "neutral") return "explain-impact explain-impact--neutral";
  return "explain-impact explain-impact--info";
}

function impactBarClass(polarity) {
  if (polarity === "elevated_risk") return "impact-bar__fill impact-bar__fill--risk";
  if (polarity === "legitimacy_support") return "impact-bar__fill impact-bar__fill--safe";
  return "impact-bar__fill impact-bar__fill--neutral";
}

function impactWidth(level) {
  if (level === "High") return "100%";
  if (level === "Medium") return "66%";
  return "33%";
}

function ImpactBadge({ level, polarity }) {
  const badgeClass =
    polarity === "elevated_risk"
      ? "impact-badge impact-badge--risk"
      : polarity === "legitimacy_support"
        ? "impact-badge impact-badge--safe"
        : "impact-badge impact-badge--neutral";

  return (
    <div className="impact-row">
      <span className={badgeClass}>{level} impact</span>
      <div className="impact-bar" aria-hidden="true">
        <div
          className={impactBarClass(polarity)}
          style={{ width: impactWidth(level) }}
        />
      </div>
    </div>
  );
}

function LimeExplanationPanel({ result, scanType }) {
  const resolvedScanType = resolveScanType(result, scanType);
  const items = normalizeExplanationItems(result, resolvedScanType);
  if (!items.length) return null;

  const sections = groupByCategory(items);

  return (
    <div className="lime-explanations">
      <h3 className="lime-explanations__heading">Why this result?</h3>
      <p className="lime-explanations__intro">{getExplanationIntro(resolvedScanType)}</p>

      {sections.map((section) => (
        <section key={section.id} className="explain-category">
          <h4 className="explain-category__title">{section.label}</h4>
          <ul className="explain-list">
            {section.items.map((item, idx) => (
              <li
                key={`${item.featureKey || item.title}-${idx}`}
                className={polarityClass(item.polarity)}
              >
                <div className="explain-card-header">
                  <div className="explain-title">{item.title}</div>
                  <ImpactBadge level={item.impactLevel} polarity={item.polarity} />
                </div>
                <p className="explain-body">{item.explanation}</p>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

export default LimeExplanationPanel;
