const API_BASE_URL = "http://localhost:8000";
const DEFAULT_ASSET_NAME = "Web Server VM";
const assetNameMap = {
  Database: "Database Server",
  Storage: "Storage Bucket",
  "Web Server": "Web Server VM",
  "Application Server": "Application Server VM",
  IAM: "IAM Role"
};
const scenarioPresets = {
  "internet-to-database": {
    assetName: "Database Server",
    graphMode: "attack-path",
    status: "Preset loaded: Internet to Database attack path"
  },
  "web-server-focus": {
    assetName: "Web Server VM",
    graphMode: "attack-path",
    status: "Preset loaded: Web Server exposure review"
  },
  "iam-review": {
    assetName: "IAM Role",
    graphMode: "risk-score",
    status: "Preset loaded: IAM risk review"
  }
};
const ATTACK_SIMULATION_STEP_DELAY_MS = 950;
const ATTACK_SIMULATION_PAUSE_POLL_MS = 120;
const attackSimulationState = {
  pathNodeIds: [],
  pathEdgePairs: [],
  running: false,
  paused: false,
  stepIndex: 0,
  runToken: 0
};
let cachedRiskAssets = null;
let riskMode = false;
let predictionMode = false;
let currentPredictions = [];
let currentGraphData = null;
let highRiskNodeIds = [];
let currentAssetAnalysis = null;
let selectedAssetName = DEFAULT_ASSET_NAME;

console.log("App loaded");

function updateStatus(message, state) {
  const statusOutput = document.getElementById("status-output") || document.getElementById("statusLog");
  if (!statusOutput) {
    return;
  }

  statusOutput.textContent = message;
  statusOutput.classList.remove("loading", "success", "error");

  if (state) {
    statusOutput.classList.add(state);
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeAssetName(assetName) {
  const requestedAsset = String(assetName || "").trim();
  return assetNameMap[requestedAsset] || requestedAsset || DEFAULT_ASSET_NAME;
}

function setAssetAnalysisFeedback(message, state) {
  const feedback = document.getElementById("asset-analysis-feedback");
  if (!feedback) {
    return;
  }

  feedback.textContent = message;
  feedback.classList.remove("loading", "success", "error");

  if (state) {
    feedback.classList.add(state);
  }
}

function renderPanelLoading(containerId, message = "Loading...") {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }

  container.innerHTML = `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function normalizeRiskLevelLabel(level, fallbackRiskScore) {
  const raw = String(level || "").trim().toUpperCase();
  if (raw === "LOW" || raw === "MEDIUM" || raw === "HIGH" || raw === "CRITICAL") {
    return raw;
  }

  const score = Number(fallbackRiskScore);
  if (Number.isFinite(score) && score >= 90) {
    return "CRITICAL";
  }

  return getRiskLevel(score);
}

function getRiskLevelToneClass(level) {
  const normalized = String(level || "").toUpperCase();
  if (normalized === "CRITICAL") {
    return "critical";
  }
  if (normalized === "HIGH") {
    return "high";
  }
  if (normalized === "MEDIUM") {
    return "medium";
  }
  return "low";
}

function getSeverityPriorityBadgeClass(value) {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "HIGH" || normalized === "P1") {
    return "badge-red";
  }
  if (normalized === "MEDIUM" || normalized === "P2") {
    return "badge-orange";
  }
  if (normalized === "LOW" || normalized === "P3") {
    return "badge-green";
  }
  return "badge-medium";
}

function formatFloat(value, digits = 2) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) {
    return "N/A";
  }
  return numericValue.toFixed(digits);
}

function clampPercent(value) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) {
    return 0;
  }

  return Math.max(0, Math.min(100, numericValue * 100));
}

function formatAssetTypeLabel(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return "Unknown";
  }

  if (/^iam[\s_-]*role$/i.test(raw) || /^iamrole$/i.test(raw)) {
    return "IAM Role";
  }

  if (/^user$/i.test(raw)) {
    return "User";
  }

  if (/^vm$/i.test(raw)) {
    return "VM";
  }

  if (/^database$/i.test(raw)) {
    return "Database";
  }

  if (/^bucket$/i.test(raw)) {
    return "Bucket";
  }

  if (/^iam$/i.test(raw)) {
    return "IAM";
  }

  if (raw === raw.toUpperCase() && raw.length <= 4) {
    return raw;
  }

  return raw
    .replace(/[_-]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function normalizeCandidateType(candidate) {
  const rawType = String(candidate?.asset_type || candidate?.type || "").trim();
  const rawLabel = String(Array.isArray(candidate?.labels) && candidate.labels.length > 0 ? candidate.labels[0] : "").trim();
  const combined = `${rawType} ${rawLabel} ${candidate?.asset_name || ""}`.toLowerCase();

  if (combined.includes("iam role") || combined.includes("iamrole") || combined.includes("identity") || combined.includes("user")) {
    return "IDENTITY";
  }

  if (combined.includes("database") || combined.includes("db")) {
    return "DATABASE";
  }

  if (combined.includes("bucket") || combined.includes("storage") || combined.includes("s3")) {
    return "BUCKET";
  }

  if (combined.includes("web") || combined.includes("vm") || combined.includes("server") || combined.includes("application") || combined.includes("compute")) {
    return "VM";
  }

  return "UNKNOWN";
}

function getCandidateReason(candidate) {
  const typeCategory = normalizeCandidateType(candidate);

  if (typeCategory === "IDENTITY") {
    return "Privilege escalation path";
  }

  if (typeCategory === "DATABASE") {
    return "Sensitive data exposure risk";
  }

  if (typeCategory === "BUCKET") {
    return "Public access / misconfiguration risk";
  }

  if (typeCategory === "VM") {
    return "Lateral movement risk";
  }

  return "Potential attack path risk";
}

function getCandidateMitigationGuidance(candidate) {
  const typeCategory = normalizeCandidateType(candidate);

  if (typeCategory === "IDENTITY") {
    return [
      "Enforce MFA for all human and service identities.",
      "Restrict IAM role trust policies and session duration.",
      "Apply least privilege permissions and review role assumptions."
    ];
  }

  if (typeCategory === "DATABASE") {
    return [
      "Encrypt sensitive data at rest and in transit.",
      "Restrict database network access to trusted sources.",
      "Rotate credentials and audit privileged access paths."
    ];
  }

  if (typeCategory === "BUCKET") {
    return [
      "Remove public access and validate bucket policies.",
      "Review ACLs, lifecycle rules, and cross-account access.",
      "Enable access logging and detect misconfiguration drift."
    ];
  }

  if (typeCategory === "VM") {
    return [
      "Segment workloads and limit east-west traffic.",
      "Tighten firewall rules and reduce exposed services.",
      "Patch guest systems and remove unnecessary privileges."
    ];
  }

  return [
    "Review access boundaries and reduce unnecessary exposure.",
    "Validate logging, alerting, and least-privilege controls.",
    "Confirm the asset is covered by a documented hardening baseline."
  ];
}

function getTopCandidateTargets(assetAnalysis, limit = 3) {
  const candidates = Array.isArray(assetAnalysis?.candidate_next_hops) ? assetAnalysis.candidate_next_hops : [];
  const deduped = [];
  const seen = new Set();

  candidates
    .slice()
    .sort((left, right) => Number(right?.combined_score || 0) - Number(left?.combined_score || 0))
    .forEach((candidate) => {
      const key = normalize(candidate?.asset_name || candidate?.node || candidate?.id || candidate?.target || "");
      if (!key || seen.has(key)) {
        return;
      }

      seen.add(key);
      deduped.push(candidate);
    });

  if (deduped.length === 0 && assetAnalysis?.predicted_next_target?.asset_name) {
    deduped.push({
      ...assetAnalysis.predicted_next_target,
      combined_score: Number(assetAnalysis.predicted_next_target?.combined_score || assetAnalysis.predicted_next_target?.confidence || 0),
      path_length: assetAnalysis.predicted_next_target?.path_length || 1,
      labels: assetAnalysis.predicted_next_target?.labels || []
    });
  }

  return deduped.slice(0, limit);
}

function getAssetAnalysisSourceName(assetAnalysis) {
  return String(assetAnalysis?.asset_name || selectedAssetName || DEFAULT_ASSET_NAME || "").trim();
}

function getAnalysisAssetType(assetAnalysis) {
  const assetName = String(assetAnalysis?.asset_name || selectedAssetName || "").trim();
  const currentRiskType = String(assetAnalysis?.current_risk?.asset_type || assetAnalysis?.asset_type || "").trim();
  const combined = `${currentRiskType} ${assetName}`.toLowerCase();

  if (combined.includes("database") || combined.includes("db")) {
    return "DATABASE";
  }

  if (combined.includes("bucket") || combined.includes("storage") || combined.includes("s3")) {
    return "BUCKET";
  }

  if (combined.includes("iam role") || combined.includes("iamrole") || combined.includes("identity") || combined.includes("user")) {
    return "IDENTITY";
  }

  if (combined.includes("web") || combined.includes("vm") || combined.includes("server") || combined.includes("application")) {
    return "VM";
  }

  return "UNKNOWN";
}

function isTerminalAssetAnalysis(assetAnalysis) {
  const assetType = getAnalysisAssetType(assetAnalysis);
  return assetType === "DATABASE" || assetType === "BUCKET";
}

function getTerminalAssetMessage(assetAnalysis) {
  if (getAnalysisAssetType(assetAnalysis) === "DATABASE") {
    return "Terminal Asset – End of Attack Path. No further lateral movement possible.";
  }

  return "No viable attack paths from this asset.";
}

function getNoReachableTargetsMessage() {
  return "No reachable next targets. This asset does not lead to further compromise paths.";
}

function getAttackNarrativeEmptyMessage() {
  return "Attack path ends at this asset.";
}

function renderTerminalBadge() {
  return '<span class="terminal-node-badge">TERMINAL NODE</span>';
}

function getGraphNodeLabel(node) {
  if (!node) {
    return "";
  }

  if (typeof node.data === "function") {
    return String(node.data("label") || node.data("name") || node.data("id") || "").trim();
  }

  const data = node.data || node;
  return String(data?.label || data?.name || data?.id || "").trim();
}

function getGraphPathNodeId(node) {
  if (!node) {
    return "";
  }

  if (typeof node.id === "function") {
    return String(node.id() || "").trim();
  }

  const data = node.data || node;
  return String(data?.id || data?.label || data?.name || "").trim();
}

function findGraphPath(sourceName, targetName) {
  const cy = window.cloudguardCy;
  if (!cy || !sourceName || !targetName) {
    return null;
  }

  const sourceNode = findNodeByAssetName(sourceName);
  const targetNode = findNodeByAssetName(targetName);

  if (!sourceNode || sourceNode.empty() || !targetNode || targetNode.empty()) {
    return null;
  }

  const startId = String(sourceNode.id());
  const goalId = String(targetNode.id());
  const queue = [startId];
  const visited = new Set([startId]);
  const previous = new Map();

  while (queue.length > 0) {
    const currentId = queue.shift();
    if (currentId === goalId) {
      break;
    }

    const currentNode = cy.getElementById(currentId);
    if (!currentNode || currentNode.empty()) {
      continue;
    }

    currentNode.outgoers("edge").forEach((edge) => {
      const nextNode = edge.target();
      const nextId = String(nextNode.id());
      if (!nextId || visited.has(nextId)) {
        return;
      }

      visited.add(nextId);
      previous.set(nextId, {
        nodeId: currentId,
        edgeId: String(edge.id())
      });
      queue.push(nextId);
    });
  }

  if (!visited.has(goalId)) {
    return null;
  }

  const nodeIds = [goalId];
  const edgeIds = [];
  let walkerId = goalId;

  while (walkerId !== startId) {
    const step = previous.get(walkerId);
    if (!step) {
      return null;
    }

    edgeIds.unshift(step.edgeId);
    nodeIds.unshift(step.nodeId);
    walkerId = step.nodeId;
  }

  const pathNodes = nodeIds
    .map((nodeId) => cy.getElementById(nodeId))
    .filter((node) => !!node && !node.empty());
  const pathEdges = edgeIds
    .map((edgeId) => cy.getElementById(edgeId))
    .filter((edge) => !!edge && !edge.empty());

  return {
    nodes: pathNodes,
    edges: pathEdges
  };
}

function buildPathStepVerb(fromLabel, toLabel, index) {
  const source = normalize(fromLabel);
  const target = normalize(toLabel);

  if (source.includes("internet")) {
    return "exposes";
  }

  if (source.includes("iamrole") || source.includes("identity") || source.includes("user")) {
    return "has access to";
  }

  if (source.includes("database")) {
    return "contains data for";
  }

  if (source.includes("bucket") || source.includes("storage")) {
    return "feeds";
  }

  if (target.includes("iamrole") || target.includes("identity") || target.includes("user")) {
    return index === 0 ? "can escalate toward" : "leads to";
  }

  return "connects to";
}

function buildAttackPathNarrative(assetAnalysis, candidate, graphPath) {
  const sourceName = getAssetAnalysisSourceName(assetAnalysis);
  const targetName = String(candidate?.asset_name || assetAnalysis?.predicted_next_target?.asset_name || "Unknown").trim();
  const sourceType = formatAssetTypeLabel(assetAnalysis?.current_risk?.asset_type || assetAnalysis?.asset_type || "");
  const targetType = formatAssetTypeLabel(candidate?.asset_type || assetAnalysis?.predicted_next_target?.asset_type || "");

  if (graphPath && Array.isArray(graphPath.nodes) && graphPath.nodes.length > 1) {
    const labels = graphPath.nodes.map((node) => getGraphNodeLabel(node) || getGraphPathNodeId(node)).filter(Boolean);
    const steps = [];

    graphPath.edges.forEach((edge, index) => {
      const fromLabel = labels[index] || getGraphNodeLabel(edge.source());
      const toLabel = labels[index + 1] || getGraphNodeLabel(edge.target());
      const verb = buildPathStepVerb(fromLabel, toLabel, index);
      steps.push({
        label: `Step ${index + 1}`,
        text: `${fromLabel} ${verb} ${toLabel}`,
        final: index === graphPath.edges.length - 1
      });
    });

    return {
      title: "Attack progression:",
      progression: labels.join(" → "),
      steps,
      sourceName,
      targetName,
      sourceType,
      targetType
    };
  }

  const fallbackSteps = [
    {
      label: "Step 1",
      text: `${sourceName} can reach ${targetName}`,
      final: true
    }
  ];

  if (targetType && targetType !== "Unknown") {
    fallbackSteps.push({
      label: "Step 2",
      text: `${targetName} is a ${targetType} target`,
      final: true
    });
  }

  return {
    title: "Attack progression:",
    progression: `${sourceName} → ${targetName}`,
    steps: fallbackSteps,
    sourceName,
    targetName,
    sourceType,
    targetType
  };
}

function highlightAnalysisPath(candidateName, options = {}) {
  const cy = window.cloudguardCy;
  if (!cy) {
    return false;
  }

  const targetName = String(candidateName || "").trim();
  const sourceName = getAssetAnalysisSourceName(currentAssetAnalysis || {});
  if (!targetName) {
    return false;
  }

  const graphPath = findGraphPath(sourceName, targetName);
  const targetNode = findNodeByAssetName(targetName);
  const sourceNode = findNodeByAssetName(sourceName);

  resetPredictionHighlight();

  if (graphPath && graphPath.nodes.length > 0) {
    cy.batch(() => {
      graphPath.nodes.forEach((node, index) => {
        node.addClass(index === graphPath.nodes.length - 1 ? "analysis-primary-target" : "analysis-path-node");
      });
      graphPath.edges.forEach((edge) => edge.addClass("analysis-path-edge"));

      if (sourceNode && !sourceNode.empty()) {
        sourceNode.addClass("analysis-source-node");
      }
    });

    if (options.focus && targetNode && !targetNode.empty()) {
      cy.animate(
        {
          fit: {
            eles: graphPath.nodes,
            padding: 75
          }
        },
        {
          duration: 280
        }
      );
    }

    if (targetNode && !targetNode.empty()) {
      showNodeDetails(targetNode.data());
    }

    return true;
  }

  if (targetNode && !targetNode.empty()) {
    cy.batch(() => {
      targetNode.addClass("analysis-primary-target");
      if (sourceNode && !sourceNode.empty()) {
        sourceNode.addClass("analysis-source-node");
      }
    });

    if (options.focus) {
      cy.animate(
        {
          fit: {
            eles: targetNode,
            padding: 75
          }
        },
        {
          duration: 280
        }
      );
    }

    showNodeDetails(targetNode.data());

    return true;
  }

  return false;
}

function renderAttackPathNarrativePanel(assetAnalysis, candidate) {
  const container = document.getElementById("asset-narrative-panel-content");
  if (!container) {
    return;
  }

  const sourceName = getAssetAnalysisSourceName(assetAnalysis);
  const targetCandidate = candidate || getTopCandidateTargets(assetAnalysis, 1)[0] || assetAnalysis?.predicted_next_target || null;
  const hasNoMovement = Array.isArray(assetAnalysis?.candidate_next_hops) && assetAnalysis.candidate_next_hops.length === 0 && !assetAnalysis?.predicted_next_target;
  if (!sourceName || hasNoMovement || !targetCandidate) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(getAttackNarrativeEmptyMessage())}</div>`;
    return;
  }

  const graphPath = findGraphPath(sourceName, targetCandidate.asset_name || "");
  const narrative = buildAttackPathNarrative(assetAnalysis, targetCandidate, graphPath);

  const stepsMarkup = narrative.steps.map((step) => `
    <li class="narrative-step ${step.final ? "final-step" : ""}">
      <span class="narrative-step-label">${escapeHtml(step.label)}</span>
      <span class="narrative-step-text">${escapeHtml(step.text)}</span>
    </li>
  `).join("");

  container.innerHTML = `
    <div class="narrative-summary">
      <p class="narrative-progress">${escapeHtml(narrative.title)} <strong>${escapeHtml(narrative.progression)}</strong></p>
      <p class="narrative-meta">Primary target: <strong class="narrative-target">${escapeHtml(formatAssetTypeLabel(targetCandidate.asset_type) || targetCandidate.asset_name)}</strong></p>
    </div>
    <ol class="narrative-step-list">
      ${stepsMarkup}
    </ol>
  `;
}

function syncAnalysisGraphHighlight(assetAnalysis, candidate) {
  const targetName = String(candidate?.asset_name || assetAnalysis?.predicted_next_target?.asset_name || "").trim();
  if (!targetName) {
    resetPredictionHighlight();
    return;
  }

  highlightAnalysisPath(targetName, { focus: false });
}

function buildCandidateDisplaySet(assetAnalysis) {
  return getTopCandidateTargets(assetAnalysis, 3).map((candidate, index) => ({
    ...candidate,
    rank: index + 1,
    reason: getCandidateReason(candidate),
    displayType: formatAssetTypeLabel(candidate?.asset_type),
    confidencePercent: clampPercent(candidate?.combined_score ?? candidate?.confidence ?? 0)
  }));
}

function registerCandidateInteractions(container, assetAnalysis, candidateList) {
  if (!container) {
    return;
  }

  const cards = container.querySelectorAll("[data-candidate-name]");
  cards.forEach((card) => {
    const candidateName = String(card.getAttribute("data-candidate-name") || "").trim();
    if (!candidateName) {
      return;
    }

    const candidate = candidateList.find((item) => String(item?.asset_name || "").trim() === candidateName) || null;
    const handlePreview = () => {
      if (candidate) {
        highlightAnalysisPath(candidate.asset_name, { focus: false });
        renderAttackPathNarrativePanel(assetAnalysis, candidate);
      }
    };

    const handleFocus = () => {
      const focused = candidate ? highlightAnalysisPath(candidate.asset_name, { focus: true }) : focusAndHighlightNodeByAssetName(candidateName, true);
      if (!focused) {
        updateStatus(`Candidate ${candidateName} not found in graph`, "error");
        return;
      }

      renderAttackPathNarrativePanel(assetAnalysis, candidate || null);
      updateStatus(`Focused candidate ${candidateName} in graph`, "success");
    };

    card.addEventListener("mouseenter", handlePreview);
    card.addEventListener("focus", handlePreview);
    card.addEventListener("mouseleave", () => {
      const primaryCandidate = candidateList[0] || null;
      if (primaryCandidate) {
        highlightAnalysisPath(primaryCandidate.asset_name, { focus: false });
        renderAttackPathNarrativePanel(assetAnalysis, primaryCandidate);
      }
    });
    card.addEventListener("blur", () => {
      const primaryCandidate = candidateList[0] || null;
      if (primaryCandidate) {
        highlightAnalysisPath(primaryCandidate.asset_name, { focus: false });
        renderAttackPathNarrativePanel(assetAnalysis, primaryCandidate);
      }
    });
    card.addEventListener("click", handleFocus);
    card.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        handleFocus();
      }
    });
  });
}

function renderAssetRiskPanel(assetAnalysis) {
  const container = document.getElementById("asset-risk-panel-content");
  if (!container) {
    return;
  }

  const assetName = assetAnalysis?.asset_name || selectedAssetName || "Unknown";
  const currentRisk = assetAnalysis?.current_risk || {};
  const riskScore = currentRisk?.risk_score;
  const riskLevel = normalizeRiskLevelLabel(currentRisk?.risk_level, riskScore);
  const explanation = currentRisk?.explanation || "No explanation provided";

  container.innerHTML = `
    <div class="metric-row">
      <span class="metric-label">Asset</span>
      <span class="metric-value">${escapeHtml(assetName)}</span>
    </div>
    <div class="metric-row">
      <span class="metric-label">Risk Score</span>
      <span class="metric-value">${escapeHtml(formatRiskValue(riskScore))}</span>
    </div>
    <div class="metric-row">
      <span class="metric-label">Risk Level</span>
      <span class="risk-level ${getRiskLevelToneClass(riskLevel)}">${escapeHtml(riskLevel)}</span>
    </div>
    <p class="card-text">${escapeHtml(explanation)}</p>
  `;
}

function renderAssetPredictionPanel(assetAnalysis, candidateList = null) {
  const container = document.getElementById("asset-prediction-panel-content");
  if (!container) {
    return;
  }

  const candidates = Array.isArray(candidateList) ? candidateList : buildCandidateDisplaySet(assetAnalysis);
  if (candidates.length === 0) {
    container.innerHTML = `
      <div class="prediction-summary terminal-summary">
        ${isTerminalAssetAnalysis(assetAnalysis) ? renderTerminalBadge() : ""}
        <div class="empty-state">${escapeHtml(getTerminalAssetMessage(assetAnalysis))}</div>
      </div>
    `;
    return;
  }

  const primaryCandidate = candidates[0];
  const primaryConfidence = clampPercent(primaryCandidate?.confidence ?? primaryCandidate?.combined_score ?? 0);
  const primaryType = formatAssetTypeLabel(primaryCandidate?.asset_type);
  const primaryReason = getCandidateReason(primaryCandidate);
  const secondaryCandidates = candidates.slice(0, 3);

  const candidateCards = secondaryCandidates.map((candidate, index) => {
    const isPrimary = index === 0;
    const scorePercent = clampPercent(candidate?.confidence ?? candidate?.combined_score ?? 0);
    const typeLabel = formatAssetTypeLabel(candidate?.asset_type);
    const reason = getCandidateReason(candidate);

    return `
      <article class="prediction-item ${isPrimary ? "primary-prediction-item" : ""}" data-candidate-name="${escapeHtml(candidate?.asset_name || "")}" tabindex="0" role="button" aria-label="Inspect ${escapeHtml(candidate?.asset_name || "candidate")}">
        <div class="prediction-item-row">
          <div class="prediction-label">
            <span class="prediction-dot"></span>
            <strong>${isPrimary ? "Primary Prediction" : `#${index + 1}`}</strong>
          </div>
          <span class="prediction-confidence">${escapeHtml(typeLabel)}</span>
        </div>
        <div class="prediction-item-row">
          <strong>${escapeHtml(candidate?.asset_name || "Unknown")}</strong>
          <span class="prediction-confidence">${escapeHtml(formatFloat(candidate?.combined_score ?? candidate?.confidence ?? 0, 2))}</span>
        </div>
        <div class="prediction-bar-track" aria-hidden="true">
          <div class="prediction-bar-fill" style="width: ${scorePercent.toFixed(1)}%"></div>
        </div>
        <p class="prediction-reason">${escapeHtml(reason)}</p>
      </article>
    `;
  }).join("");

  container.innerHTML = `
    <div class="prediction-summary">
      <div class="primary-prediction-banner">
        <div class="primary-prediction-header">
          <span class="primary-prediction-badge">Primary Prediction</span>
          <span class="primary-prediction-confidence">${primaryConfidence.toFixed(1)}%</span>
        </div>
        <div class="primary-prediction-name">${escapeHtml(primaryCandidate?.asset_name || "Unknown")}</div>
        <div class="primary-prediction-meta">${escapeHtml(primaryType)} · ${escapeHtml(primaryReason)}</div>
        <div class="prediction-bar-track">
          <div class="prediction-bar-fill" style="width: ${primaryConfidence.toFixed(1)}%"></div>
        </div>
      </div>
      <div class="prediction-summary-note">Top 3 candidates ranked by combined score.</div>
    </div>
    <div class="prediction-stack">${candidateCards}</div>
  `;

  registerCandidateInteractions(container, assetAnalysis, candidates);
}

function renderAssetCandidatesPanel(assetAnalysis, candidateList = null) {
  const container = document.getElementById("asset-candidates-panel-content");
  if (!container) {
    return;
  }

  const candidates = Array.isArray(candidateList) ? candidateList : buildCandidateDisplaySet(assetAnalysis);
  if (candidates.length === 0) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(getNoReachableTargetsMessage())}</div>`;
    return;
  }

  const cards = candidates.map((candidate, index) => {
    const candidateName = String(candidate?.asset_name || "Unknown");
    const isPrimary = index === 0;
    return `
      <article class="candidate-card ${isPrimary ? "candidate-card-primary" : ""}" data-candidate-name="${escapeHtml(candidateName)}" tabindex="0" role="button" aria-label="Focus ${escapeHtml(candidateName)} in attack graph">
        <div class="candidate-card-header">
          <span class="candidate-rank">${isPrimary ? "Primary" : `#${index + 1}`}</span>
          <span class="candidate-type">${escapeHtml(formatAssetTypeLabel(candidate?.asset_type))}</span>
        </div>
        <h4 class="card-title">${escapeHtml(candidateName)}</h4>
        <p class="card-text">${escapeHtml(getCandidateReason(candidate))}</p>
        <div class="metric-row">
          <span class="metric-label">Combined Score</span>
          <span class="metric-value">${escapeHtml(formatFloat(candidate?.combined_score, 2))}</span>
        </div>
        <div class="metric-row">
          <span class="metric-label">Path Length</span>
          <span class="metric-value">${escapeHtml(String(candidate?.path_length ?? "N/A"))}</span>
        </div>
      </article>
    `;
  }).join("");

  container.innerHTML = `<div class="candidate-grid">${cards}</div>`;
  registerCandidateInteractions(container, assetAnalysis, candidates);
}

function renderRelatedHighRiskAssets(assets) {
  const container = document.getElementById("related-high-risk-assets");
  if (!container) {
    return;
  }

  const safeAssets = Array.isArray(assets) ? assets : [];
  if (safeAssets.length === 0) {
    container.innerHTML = `<div class="empty-state">No data available</div>`;
    return;
  }

  const cards = safeAssets
    .map((asset) => {
      const level = String(asset?.risk_level || "LOW").toUpperCase();
      return `
        <article class="risk-card ${escapeHtml(level.toLowerCase())}" data-asset-name="${escapeHtml(asset?.name || "")}">
          <div class="risk-title">${escapeHtml(asset?.name || "Unknown")} <span class="badge ${getRiskBadgeClass(level)}">${escapeHtml(level)}</span></div>
          <div class="risk-score">Risk Score: ${escapeHtml(formatRiskValue(asset?.risk_score))}</div>
          <div class="risk-reason">Reason: ${escapeHtml(asset?.reason || "No reason provided")}</div>
        </article>
      `;
    })
    .join("");

  container.innerHTML = cards;

  container.querySelectorAll(".risk-card").forEach((card) => {
    card.addEventListener("click", () => {
      const assetName = card.getAttribute("data-asset-name") || "";
      focusAndHighlightNodeByAssetName(assetName, true);
    });
  });
}

function findNodeByAssetName(assetName) {
  const cy = window.cloudguardCy;
  const name = String(assetName || "").trim();

  if (!cy || !name) {
    return null;
  }

  const normalizedName = normalize(name);
  return cy.nodes().filter((node) => {
    const label = normalize(node.data("label") || node.data("id") || node.id());
    return label === normalizedName;
  }).first();
}

function focusAndHighlightNodeByAssetName(assetName, animate = false) {
  const cy = window.cloudguardCy;
  const node = findNodeByAssetName(assetName);

  if (!cy || !node || node.empty()) {
    return false;
  }

  cy.batch(() => {
    cy.nodes().removeClass("predicted-focus pulse");
    node.addClass("predicted-focus");
  });

  if (animate) {
    cy.animate(
      {
        fit: {
          eles: node,
          padding: 65
        }
      },
      { duration: 350 }
    );
  }

  node.addClass("pulse");
  setTimeout(() => {
    if (window.cloudguardCy) {
      node.removeClass("pulse");
    }
  }, 480);

  highlightConnectedEdges(node.id());
  showNodeDetails(node.data());
  return true;
}

function clearGraphSearchHighlight() {
  const cy = window.cloudguardCy;
  if (!cy) {
    return;
  }

  cy.batch(() => {
    cy.elements().removeClass("graph-search-dimmed graph-search-match graph-search-edge");
  });
}

function searchGraphAsset(assetName, options = {}) {
  const cy = window.cloudguardCy;
  const query = String(assetName || "").trim();
  const { focus = true, announce = true } = options;

  clearGraphSearchHighlight();

  if (!cy || !query) {
    return false;
  }

  const normalizedQuery = normalize(query);
  const matches = cy.nodes().filter((node) => {
    const label = normalize(node.data("label") || node.data("id") || node.id());
    return label.includes(normalizedQuery);
  });

  if (!matches || matches.empty()) {
    if (announce) {
      updateStatus(`No graph asset found for "${query}"`, "error");
    }
    return false;
  }

  const connectedEdges = matches.connectedEdges();
  cy.batch(() => {
    cy.elements().addClass("graph-search-dimmed");
    matches.removeClass("graph-search-dimmed").addClass("graph-search-match");
    connectedEdges.removeClass("graph-search-dimmed").addClass("graph-search-edge");
    connectedEdges.connectedNodes().removeClass("graph-search-dimmed");
  });

  if (focus) {
    cy.animate(
      {
        fit: {
          eles: matches.union(connectedEdges),
          padding: 80
        }
      },
      { duration: 320 }
    );
  }

  const primaryMatch = matches.first();
  if (primaryMatch && !primaryMatch.empty()) {
    showNodeDetails(primaryMatch.data());
  }

  if (announce) {
    updateStatus(`Focused ${matches.length} matching asset${matches.length === 1 ? "" : "s"}`, "success");
  }
  return true;
}

function highlightPredictedTargetInGraph(assetAnalysis) {
  const primaryCandidate = getTopCandidateTargets(assetAnalysis, 1)[0] || assetAnalysis?.predicted_next_target || null;
  const predictedAssetName = String(primaryCandidate?.asset_name || "").trim();
  if (!predictedAssetName) {
    resetPredictionHighlight();
    return;
  }

  highlightAnalysisPath(predictedAssetName, { focus: false });
}

function buildRecommendationsText(mitigations, assetName) {
  const safeMitigations = Array.isArray(mitigations) ? mitigations : [];
  const title = `CloudGuard AI Mitigation Recommendations\nAsset: ${assetName || "Unknown"}`;
  const lines = safeMitigations.map((item, index) => {
    const recommendation = item?.recommendation || "N/A";
    const reason = item?.reason || "N/A";
    const severity = item?.severity || "N/A";
    const priority = item?.priority || "N/A";
    return `${index + 1}. ${item?.title || "Untitled"}\n   Severity: ${severity} | Priority: ${priority}\n   Recommendation: ${recommendation}\n   Reason: ${reason}`;
  });

  return [title, "", ...lines].join("\n");
}

function renderAssetMitigationPanel(assetAnalysis, candidateList = null) {
  const container = document.getElementById("asset-mitigations-panel-content");
  const copyButton = document.getElementById("copy-recommendations-btn");
  if (!container) {
    return;
  }

  const mitigations = Array.isArray(assetAnalysis?.mitigations) ? assetAnalysis.mitigations : [];
  const candidates = Array.isArray(candidateList) ? candidateList : buildCandidateDisplaySet(assetAnalysis);
  const primaryCandidate = candidates[0] || assetAnalysis?.predicted_next_target || null;
  const contextualMitigations = primaryCandidate ? getCandidateMitigationGuidance(primaryCandidate) : [];

  if (copyButton) {
    copyButton.disabled = mitigations.length === 0 && contextualMitigations.length === 0;
  }

  const contextualMarkup = contextualMitigations.length > 0
    ? `
      <div class="contextual-mitigation-block">
        <div class="contextual-mitigation-heading">Context-aware guidance for ${escapeHtml(formatAssetTypeLabel(primaryCandidate?.asset_type || "Unknown"))}</div>
        <ul class="contextual-mitigation-list">
          ${contextualMitigations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
      </div>
    `
    : "";

  const cards = mitigations.length > 0
    ? mitigations
        .map((item) => {
          const severity = String(item?.severity || "LOW").toUpperCase();
          const priority = String(item?.priority || "P3").toUpperCase();

          return `
            <article class="mitigation-card">
              <h4 class="card-title">${escapeHtml(item?.title || "Untitled")}</h4>
              <div class="badge-row">
                <span class="badge ${getSeverityPriorityBadgeClass(severity)}">${escapeHtml(severity)}</span>
                <span class="badge ${getSeverityPriorityBadgeClass(priority)}">${escapeHtml(priority)}</span>
              </div>
              <p class="card-text">${escapeHtml(item?.recommendation || "No recommendation provided")}</p>
              <p class="card-text"><strong>Reason:</strong> ${escapeHtml(item?.reason || "No reason provided")}</p>
            </article>
          `;
        })
        .join("")
    : `<div class="empty-state">No backend mitigation data available</div>`;

  container.innerHTML = `
    ${contextualMarkup}
    <div class="mitigation-grid">${cards}</div>
  `;
}

function renderAssetAnalysisDashboard(assetAnalysis) {
  const candidateList = buildCandidateDisplaySet(assetAnalysis);
  const primaryCandidate = candidateList[0] || assetAnalysis?.predicted_next_target || null;

  renderAssetRiskPanel(assetAnalysis);
  renderAssetPredictionPanel(assetAnalysis, candidateList);
  renderAssetCandidatesPanel(assetAnalysis, candidateList);
  renderAttackPathNarrativePanel(assetAnalysis, primaryCandidate);
  renderAssetMitigationPanel(assetAnalysis, candidateList);
  renderExplainabilityPanel(assetAnalysis, primaryCandidate);
  if (candidateList.length > 0) {
    syncAnalysisGraphHighlight(assetAnalysis, primaryCandidate);
  } else {
    resetPredictionHighlight();
  }

  // Also apply static prediction highlight for quick visibility (non-simulation classes)
  try {
    const cy = window.cloudguardCy;
    const sourceElem = findNodeByAssetName(getAssetAnalysisSourceName(assetAnalysis || {}));
    let sourceId = sourceElem && !sourceElem.empty() ? String(sourceElem.id()) : null;
    let targetId = null;

    if (primaryCandidate) {
      if (primaryCandidate.node) {
        targetId = String(primaryCandidate.node);
      } else if (primaryCandidate.asset_name) {
        const targetElem = findNodeByAssetName(primaryCandidate.asset_name);
        if (targetElem && !targetElem.empty()) targetId = String(targetElem.id());
      }
    }

    if (sourceId && targetId) {
      highlightPredictionPath(sourceId, targetId);
    }
  } catch (e) {
    // fail gracefully
  }
}

// Explainability helper: returns human-readable explanation string
function getPredictionExplanation(data) {
  if (!data) return "No explanation available";

  // Minimal deterministic explanation per spec; real data could be inserted here.
  return "High exposure combined with identity and network risks, along with a short attack path, increases the likelihood of compromise.";
}

function renderExplainabilityPanel(assetAnalysis, primaryCandidate) {
  const container = document.getElementById("prediction-explainability-content");
  const factorsContainer = document.getElementById("explainability-factors");
  const textContainer = document.getElementById("explainability-text");

  if (!container || !factorsContainer || !textContainer) return;

  const prediction = primaryCandidate || assetAnalysis?.predicted_next_target || null;

  const exposure = assetAnalysis?.exposure_score ?? assetAnalysis?.current_risk?.exposure_score ?? null;
  const identity = assetAnalysis?.identity_risk_score ?? assetAnalysis?.current_risk?.identity_risk_score ?? null;
  const network = assetAnalysis?.network_risk_score ?? assetAnalysis?.current_risk?.network_risk_score ?? null;
  const pathLen = assetAnalysis?.shortest_path_length ?? assetAnalysis?.predicted_next_target?.path_length ?? null;

  const factorLines = [];
  factorLines.push(`<div><strong>exposure_score:</strong> ${exposure !== null ? escapeHtml(String(formatFloat(exposure, 2))) : "Data not available"}</div>`);
  factorLines.push(`<div><strong>identity_risk_score:</strong> ${identity !== null ? escapeHtml(String(formatFloat(identity, 2))) : "Data not available"}</div>`);
  factorLines.push(`<div><strong>network_risk_score:</strong> ${network !== null ? escapeHtml(String(formatFloat(network, 2))) : "Data not available"}</div>`);
  factorLines.push(`<div><strong>shortest_path_length:</strong> ${pathLen !== null ? escapeHtml(String(pathLen)) : "Data not available"}</div>`);

  factorsContainer.innerHTML = `<div class="explainability-list">${factorLines.join("")}</div>`;
  textContainer.textContent = getPredictionExplanation(prediction || assetAnalysis) || "No explanation available";
}

// Highlight predicted static path (source node, target node, and connecting edge)
function highlightPredictionPath(sourceId, targetId) {
  const cy = window.cloudguardCy;
  if (!cy) return;

  cy.elements().removeClass("prediction-source prediction-target prediction-edge");

  const sourceNode = sourceId ? cy.getElementById(String(sourceId)) : null;
  const targetNode = targetId ? cy.getElementById(String(targetId)) : null;

  let edge = null;
  if (sourceNode && targetNode && !sourceNode.empty() && !targetNode.empty()) {
    edge = cy.edges().filter(e => String(e.source().id()) === String(sourceNode.id()) && String(e.target().id()) === String(targetNode.id()));
  }

  if (sourceNode && !sourceNode.empty()) sourceNode.addClass("prediction-source");
  if (targetNode && !targetNode.empty()) targetNode.addClass("prediction-target");
  if (edge && edge.length > 0) edge.addClass("prediction-edge");
}

function downloadJSON(data) {
  try {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cloudguard-analysis.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Export failed", err);
    updateStatus("Export failed", "error");
  }
}

function exportCurrentAnalysis() {
  const currentAsset = selectedAssetName || null;
  const riskData = currentAssetAnalysis?.current_risk || null;
  const predictionData = currentAssetAnalysis?.predicted_next_target || (currentPredictions && currentPredictions.length > 0 ? currentPredictions[0] : null);
  const nextTargets = Array.isArray(currentAssetAnalysis?.candidate_next_hops) ? currentAssetAnalysis.candidate_next_hops : (currentPredictions || []);
  const mitigations = Array.isArray(currentAssetAnalysis?.mitigations) ? currentAssetAnalysis.mitigations : [];

  const exportData = {
    asset: currentAsset,
    risk: riskData,
    prediction: predictionData,
    candidates: nextTargets,
    mitigations: mitigations
  };

  downloadJSON(exportData);
}

async function fetchAssetAnalysis(assetName) {
  const requestedAsset = String(assetName || "").trim() || DEFAULT_ASSET_NAME;
  const normalizedAsset = normalizeAssetName(requestedAsset);
  selectedAssetName = normalizedAsset;

  renderPanelLoading("asset-risk-panel-content", "Analyzing attack paths...");
  renderPanelLoading("asset-prediction-panel-content", "Analyzing attack paths...");
  renderPanelLoading("asset-candidates-panel-content", "Analyzing attack paths...");
  renderPanelLoading("asset-mitigations-panel-content", "Analyzing attack paths...");
  renderPanelLoading("asset-narrative-panel-content", "Analyzing attack paths...");

  setAssetAnalysisFeedback(`Analyzing attack paths for ${normalizedAsset}...`, "loading");
  updateStatus(`Analyzing attack paths for ${normalizedAsset}...`, "loading");

  try {
    const encodedAsset = encodeURIComponent(normalizedAsset);
    const response = await fetch(`${API_BASE_URL}/asset-analysis/${encodedAsset}`, {
      method: "GET"
    });

    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const errorPayload = await response.json();
        if (errorPayload?.detail) {
          detail = String(errorPayload.detail);
        }
      } catch (_error) {
        // Ignore JSON parse error and preserve HTTP status fallback.
      }

      throw new Error(detail);
    }

    const payload = await response.json();
    currentAssetAnalysis = payload && typeof payload === "object" ? payload : {};

    const normalizedAssetName = normalizeAssetName(currentAssetAnalysis?.asset_name || normalizedAsset);
    selectedAssetName = normalizedAssetName;

    const selectorInput = document.getElementById("asset-selector-input");
    if (selectorInput) {
      selectorInput.value = normalizedAssetName;
    }

    renderAssetAnalysisDashboard(currentAssetAnalysis);
    await refreshRelatedHighRiskAssets({ silent: true });
    setAssetAnalysisFeedback(`Loaded analysis for ${normalizedAssetName}`, "success");
    updateStatus(`Asset analysis loaded for ${normalizedAssetName}`, "success");
  } catch (error) {
    currentAssetAnalysis = null;
    renderAssetAnalysisDashboard(currentAssetAnalysis);

    const message = error instanceof Error ? error.message : "Failed to load asset analysis";
    setAssetAnalysisFeedback(`Failed to load analysis: ${message}`, "error");
    updateStatus("Failed to load asset analysis", "error");
  }
}

async function copyRecommendationsToClipboard() {
  const mitigations = Array.isArray(currentAssetAnalysis?.mitigations) ? currentAssetAnalysis.mitigations : [];
  const primaryCandidate = getTopCandidateTargets(currentAssetAnalysis, 1)[0] || currentAssetAnalysis?.predicted_next_target || null;
  const contextualGuidance = primaryCandidate ? getCandidateMitigationGuidance(primaryCandidate) : [];

  if (mitigations.length === 0 && contextualGuidance.length === 0) {
    setAssetAnalysisFeedback("No mitigation recommendations to copy", "error");
    return;
  }

  const contextualCopy = contextualGuidance.length > 0
    ? `\nContext-aware guidance for ${formatAssetTypeLabel(primaryCandidate?.asset_type || "Unknown")}:\n${contextualGuidance.map((item, index) => `${index + 1}. ${item}`).join("\n")}`
    : "";

  const copyText = `${buildRecommendationsText(mitigations, currentAssetAnalysis?.asset_name || selectedAssetName)}${contextualCopy}`.trim();

  try {
    if (!navigator?.clipboard?.writeText) {
      throw new Error("Clipboard API unavailable");
    }

    await navigator.clipboard.writeText(copyText);
    setAssetAnalysisFeedback("Recommendations copied to clipboard", "success");
  } catch (error) {
    console.error(error);
    setAssetAnalysisFeedback("Copy failed. Clipboard permissions may be blocked.", "error");
  }
}

function getRiskLevel(risk) {
  const numericRisk = Number(risk);
  if (!Number.isFinite(numericRisk)) {
    return "LOW";
  }

  if (numericRisk > 70) {
    return "HIGH";
  }

  if (numericRisk >= 40) {
    return "MEDIUM";
  }

  return "LOW";
}

function getRiskBadgeClass(level) {
  if (level === "HIGH") {
    return "badge-high";
  }

  if (level === "MEDIUM") {
    return "badge-medium";
  }

  return "badge-low";
}

function formatRiskValue(risk) {
  const numericRisk = Number(risk);
  if (!Number.isFinite(numericRisk)) {
    return "N/A";
  }

  const rounded = Math.round(numericRisk * 100) / 100;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(2);
}

function getRiskReason(assetName) {
  const reasons = {
    "IAM Role": "Privilege misconfiguration risk",
    "Database Server": "Sensitive data exposure risk",
    "Web Server": "Internet exposed attack surface",
    "Web Server VM": "Internet exposed attack surface",
    "Application Server": "Internal lateral movement risk",
    "Application Server VM": "Internal lateral movement risk",
    "Storage Bucket": "Public access misconfiguration risk"
  };

  return reasons[assetName] || "Potential attack surface risk";
}

function normalize(str) {
  return String(str || "")
    .toLowerCase()
    .replace(/\s+/g, "")
    .replace(/[^a-z0-9]/g, "");
}

function getRiskSummaryMessage(level) {
  if (level === "HIGH") {
    return "System is at high risk. Immediate action required.";
  }

  if (level === "MEDIUM") {
    return "System risk is moderate. Key assets need attention.";
  }

  return "System risk is low. Continue monitoring.";
}

function normalizeRiskAssets(topAssets) {
  if (!Array.isArray(topAssets)) {
    return [];
  }

  return topAssets
    .map((asset) => {
      const id = String(asset?.id || asset?.asset_id || "").trim();
      const name = asset?.asset_name || asset?.asset || asset?.name || "Unknown";
      const riskRaw = asset?.risk_score ?? asset?.risk;
      const risk_score = Number(riskRaw);
      const normalizedRiskScore = Number.isFinite(risk_score) ? risk_score : null;
      const risk_level = asset?.risk_level || getRiskLevel(normalizedRiskScore);
      const reason = asset?.reason || asset?.description || asset?.details || asset?.summary || getRiskReason(name);

      return {
        id,
        name,
        risk_score: normalizedRiskScore,
        risk_level,
        reason
      };
    })
    .filter((asset) => asset.name !== "Unknown")
    .sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0));
}

function resetHighlight() {
  if (!window.cloudguardCy) {
    return;
  }

  window.cloudguardCy.nodes().removeClass("high-risk medium-risk low-risk");
  window.cloudguardCy.edges().removeClass("highlighted-edge");
}

function resetPredictionHighlight() {
  if (!window.cloudguardCy) {
    return;
  }

  window.cloudguardCy.nodes().removeClass("predicted risk-predicted predicted-focus analysis-primary-target analysis-path-node analysis-source-node");
  window.cloudguardCy.edges().removeClass("highlighted analysis-path-edge hover-highlighted-edge highlighted-edge");
}

function getAttackSimulationNodeIds(attackPathData) {
  const graphNodes = attackPathData?.graph?.nodes;
  if (Array.isArray(graphNodes) && graphNodes.length > 0) {
    return graphNodes
      .map((node) => String(node?.data?.id || node?.data?.label || node?.data?.name || node?.id || "").trim())
      .filter(Boolean);
  }

  const summaryPaths = attackPathData?.summary?.paths;
  if (Array.isArray(summaryPaths) && summaryPaths.length > 0) {
    const firstPath = summaryPaths[0];
    if (Array.isArray(firstPath?.nodes)) {
      return firstPath.nodes.map((node) => String(node || "").trim()).filter(Boolean);
    }
  }

  return [];
}

function getAttackSimulationEdgePairs(attackPathData) {
  const graphEdges = attackPathData?.graph?.edges;
  if (Array.isArray(graphEdges) && graphEdges.length > 0) {
    return graphEdges
      .map((edge) => ({
        source: String(edge?.data?.source || "").trim(),
        target: String(edge?.data?.target || "").trim()
      }))
      .filter((edge) => edge.source && edge.target);
  }

  const nodeIds = getAttackSimulationNodeIds(attackPathData);
  const edgePairs = [];
  for (let index = 0; index < nodeIds.length - 1; index += 1) {
    edgePairs.push({
      source: nodeIds[index],
      target: nodeIds[index + 1]
    });
  }

  return edgePairs;
}

function getSimulationPanelElement(elementId) {
  return document.getElementById(elementId);
}

function getSimulationNodeElement(nodeId) {
  const cy = window.cloudguardCy;
  if (!cy || !nodeId) {
    return null;
  }

  const node = cy.getElementById(String(nodeId));
  return node && !node.empty() ? node : null;
}

function getSimulationEdgeElement(sourceId, targetId) {
  const cy = window.cloudguardCy;
  if (!cy || !sourceId || !targetId) {
    return null;
  }

  const edge = cy.edges().filter((candidate) => {
    return String(candidate.source().id()) === String(sourceId) && String(candidate.target().id()) === String(targetId);
  });

  return edge && edge.length > 0 ? edge[0] : null;
}

function clearSimulationHighlightClasses() {
  const cy = window.cloudguardCy;
  if (!cy) {
    return;
  }

  cy.batch(() => {
    cy.nodes().removeClass("sim-visited sim-active");
    cy.edges().removeClass("sim-visited-edge sim-active-edge");
  });
}

function getAttackSimulationRiskSummary(node) {
  const nodeLabel = normalize(getGraphNodeLabel(node));
  const nodeId = normalize(getGraphPathNodeId(node));
  const summaryMap = window.latestRiskSummary?.assetRiskByName || {};
  const summaryEntries = Object.entries(summaryMap);

  for (const [assetName, summary] of summaryEntries) {
    const normalizedAssetName = normalize(assetName);
    if (normalizedAssetName && (normalizedAssetName === nodeLabel || normalizedAssetName === nodeId)) {
      return summary;
    }
  }

  const normalizedAssets = Array.isArray(window.latestRiskAssets) ? window.latestRiskAssets : [];
  return normalizedAssets.find((asset) => {
    const assetName = normalize(asset?.name || asset?.asset_name || asset?.asset || "");
    const assetId = normalize(asset?.id || "");
    return assetName === nodeLabel || assetName === nodeId || assetId === nodeId;
  }) || null;
}

function getAttackSimulationProbability(node) {
  const nodeLabel = normalize(getGraphNodeLabel(node));
  const nodeId = normalize(getGraphPathNodeId(node));
  const predictions = normalizePredictionTargets(window.latestAttackPathData?.prediction?.next_targets || []);

  let bestPrediction = null;
  predictions.forEach((prediction) => {
    const candidateId = normalize(prediction?.node || prediction?.id || prediction?.asset_name || prediction?.name || prediction?.label || "");
    if (candidateId !== nodeId && candidateId !== nodeLabel) {
      return;
    }

    if (!bestPrediction || Number(prediction?.probability || 0) > Number(bestPrediction?.probability || 0)) {
      bestPrediction = prediction;
    }
  });

  if (bestPrediction) {
    return Number(bestPrediction?.probability);
  }

  return Number.NaN;
}

function formatAttackSimulationProbability(probability) {
  const numericProbability = Number(probability);
  if (!Number.isFinite(numericProbability)) {
    return "-";
  }

  const percentage = numericProbability > 1 ? numericProbability : numericProbability * 100;
  return `${percentage.toFixed(1)}%`;
}

function getAttackStepDescription(nodeLabel) {
  const label = String(nodeLabel || "").toLowerCase();

  if (label.includes("internet")) {
    return "Attacker begins from external network";
  }

  if (label.includes("web")) {
    return "Exploiting publicly exposed service";
  }

  if (label.includes("application")) {
    return "Lateral movement inside network";
  }

  if (label.includes("database")) {
    return "Accessing sensitive data";
  }

  return "Advancing through attack path";
}

function updateAttackSimulationControls() {
  const simulateButton = getSimulationPanelElement("simulate-attack-button");
  const pauseButton = getSimulationPanelElement("pause-simulation-button");
  const resumeButton = getSimulationPanelElement("resume-simulation-button");
  const resetButton = getSimulationPanelElement("reset-simulation-button");
  const hasLoadedPath = attackSimulationState.pathNodeIds.length > 0;

  if (simulateButton) {
    simulateButton.disabled = !hasLoadedPath || attackSimulationState.running;
  }

  if (pauseButton) {
    pauseButton.disabled = !attackSimulationState.running || attackSimulationState.paused;
  }

  if (resumeButton) {
    resumeButton.disabled = !attackSimulationState.running || !attackSimulationState.paused;
  }

  if (resetButton) {
    resetButton.disabled = !hasLoadedPath && !attackSimulationState.running && attackSimulationState.stepIndex === 0;
  }
}

function updateAttackSimulationPanel() {
  const stateLabel = getSimulationPanelElement("attack-simulation-state");
  const stepLabel = getSimulationPanelElement("attack-simulation-step");
  const assetLabel = getSimulationPanelElement("attack-simulation-asset");
  const actionLabel = getSimulationPanelElement("attack-simulation-action");
  const riskLabel = getSimulationPanelElement("attack-simulation-risk");
  const probabilityLabel = getSimulationPanelElement("attack-simulation-probability");
  const summaryLabel = getSimulationPanelElement("attack-simulation-summary");
  const totalSteps = attackSimulationState.pathNodeIds.length;
  const hasLoadedPath = totalSteps > 0;
  const safeStepIndex = totalSteps > 0 ? Math.min(attackSimulationState.stepIndex, totalSteps - 1) : 0;
  const currentNodeId = hasLoadedPath ? attackSimulationState.pathNodeIds[safeStepIndex] : null;
  const currentNode = currentNodeId ? getSimulationNodeElement(currentNodeId) : null;
  const nodeData = currentNode && !currentNode.empty() ? currentNode.data() : null;
  const riskSummary = currentNode ? getAttackSimulationRiskSummary(currentNode) : null;
  const riskScore = Number.isFinite(Number(riskSummary?.risk_score ?? riskSummary?.risk))
    ? (riskSummary?.risk_score ?? riskSummary?.risk)
    : Number.isFinite(Number(nodeData?.risk_score))
      ? nodeData?.risk_score
      : null;
  const nodeLabel = currentNode ? getGraphNodeLabel(currentNode) || getGraphPathNodeId(currentNode) || "Unknown" : hasLoadedPath ? "Unknown" : "No attack path loaded";
  const probability = currentNode ? getAttackSimulationProbability(currentNode) : Number.NaN;

  let statusText = "No attack path loaded";
  if (attackSimulationState.running) {
    statusText = attackSimulationState.paused ? "Paused" : "Running";
  } else if (hasLoadedPath) {
    statusText = attackSimulationState.stepIndex >= totalSteps ? "Completed" : "Ready";
  }

  if (stateLabel) {
    stateLabel.textContent = statusText;
  }

  if (stepLabel) {
    stepLabel.textContent = hasLoadedPath ? `${safeStepIndex + 1} / ${totalSteps}` : "0 / 0";
  }

  if (assetLabel) {
    assetLabel.textContent = nodeLabel;
  }

  if (actionLabel) {
    actionLabel.textContent = currentNode ? getAttackStepDescription(nodeLabel) : "-";
  }

  if (riskLabel) {
    riskLabel.textContent = riskScore === null ? "Entry Point" : formatRiskValue(riskScore);
  }

  if (probabilityLabel) {
    probabilityLabel.textContent = formatAttackSimulationProbability(probability);
  }

  if (summaryLabel) {
    if (!hasLoadedPath) {
      summaryLabel.textContent = "Load an attack path to simulate each hop.";
    } else if (attackSimulationState.running && attackSimulationState.paused) {
      summaryLabel.textContent = "Simulation paused at the current step.";
    } else if (attackSimulationState.running) {
      summaryLabel.textContent = "Simulation is traversing the attack path.";
    } else if (attackSimulationState.stepIndex >= totalSteps && totalSteps > 0) {
      summaryLabel.textContent = "Simulation finished. Use Reset Simulation to clear highlights.";
    } else {
      summaryLabel.textContent = "Attack path ready for simulation.";
    }
  }

  updateAttackSimulationControls();
}

function setLoadedAttackPathSimulation(pathData) {
  attackSimulationState.pathNodeIds = getAttackSimulationNodeIds(pathData);
  attackSimulationState.pathEdgePairs = getAttackSimulationEdgePairs(pathData);
  attackSimulationState.stepIndex = 0;
  attackSimulationState.running = false;
  attackSimulationState.paused = false;
  attackSimulationState.runToken += 1;
  updateAttackSimulationPanel();
}

function clearLoadedAttackPathSimulation() {
  clearSimulationHighlightClasses();
  attackSimulationState.pathNodeIds = [];
  attackSimulationState.pathEdgePairs = [];
  attackSimulationState.stepIndex = 0;
  attackSimulationState.running = false;
  attackSimulationState.paused = false;
  attackSimulationState.runToken += 1;
  updateAttackSimulationPanel();
}

function resetSimulationState() {
  attackSimulationState.running = false;
  attackSimulationState.paused = false;
  attackSimulationState.stepIndex = 0;
  attackSimulationState.runToken += 1;
  clearSimulationHighlightClasses();
  updateAttackSimulationPanel();
}

function pauseSimulation() {
  if (!attackSimulationState.running || attackSimulationState.paused) {
    return;
  }

  attackSimulationState.paused = true;
  updateAttackSimulationPanel();
}

function resumeSimulation() {
  if (!attackSimulationState.running || !attackSimulationState.paused) {
    return;
  }

  attackSimulationState.paused = false;
  updateAttackSimulationPanel();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForSimulationDelay(runToken, delayMs) {
  let remaining = Math.max(0, Number(delayMs) || 0);

  while (remaining > 0) {
    if (attackSimulationState.runToken !== runToken || !attackSimulationState.running) {
      return false;
    }

    if (attackSimulationState.paused) {
      await sleep(ATTACK_SIMULATION_PAUSE_POLL_MS);
      continue;
    }

    const slice = Math.min(ATTACK_SIMULATION_PAUSE_POLL_MS, remaining);
    await sleep(slice);
    remaining -= slice;
  }

  return attackSimulationState.runToken === runToken && attackSimulationState.running;
}

function applySimulationStep(stepIndex) {
  const cy = window.cloudguardCy;
  const nodeIds = attackSimulationState.pathNodeIds;
  const edgePairs = attackSimulationState.pathEdgePairs;

  if (!cy || !Array.isArray(nodeIds) || nodeIds.length === 0) {
    return null;
  }

  const safeIndex = Math.max(0, Math.min(stepIndex, nodeIds.length - 1));
  const currentNodeId = nodeIds[safeIndex];
  const currentNode = getSimulationNodeElement(currentNodeId);

  if (!currentNode) {
    return null;
  }

  cy.batch(() => {
    nodeIds.forEach((nodeId, index) => {
      const node = getSimulationNodeElement(nodeId);
      if (!node) {
        return;
      }

      node.removeClass("sim-visited sim-active");
      if (index < safeIndex) {
        node.addClass("sim-visited");
      } else if (index === safeIndex) {
        node.addClass("sim-active");
      }
    });

    edgePairs.forEach((edgePair, index) => {
      const edge = getSimulationEdgeElement(edgePair.source, edgePair.target);
      if (!edge) {
        return;
      }

      edge.removeClass("sim-visited-edge sim-active-edge");
      if (index < safeIndex) {
        edge.addClass("sim-visited-edge");
      } else if (index === safeIndex && safeIndex < edgePairs.length) {
        edge.addClass("sim-active-edge");
      }
    });
  });

  cy.animate(
    {
      center: { eles: currentNode }
    },
    {
      duration: 240
    }
  );

  showNodeDetails(currentNode.data());
  attackSimulationState.stepIndex = safeIndex;
  updateAttackSimulationPanel();
  return currentNode;
}

async function startSimulation() {
  if (attackSimulationState.running) {
    return;
  }

  if (attackSimulationState.pathNodeIds.length === 0) {
    updateAttackSimulationPanel();
    return;
  }

  clearSimulationHighlightClasses();
  attackSimulationState.running = true;
  attackSimulationState.paused = false;
  attackSimulationState.stepIndex = 0;
  attackSimulationState.runToken += 1;
  const runToken = attackSimulationState.runToken;

  updateAttackSimulationPanel();

  const totalSteps = attackSimulationState.pathNodeIds.length;

  for (let stepIndex = 0; stepIndex < totalSteps; stepIndex += 1) {
    if (attackSimulationState.runToken !== runToken || !attackSimulationState.running) {
      return;
    }

    while (attackSimulationState.paused) {
      if (attackSimulationState.runToken !== runToken || !attackSimulationState.running) {
        return;
      }

      await sleep(ATTACK_SIMULATION_PAUSE_POLL_MS);
    }

    const currentNode = applySimulationStep(stepIndex);
    if (!currentNode) {
      break;
    }

    attackSimulationState.stepIndex = stepIndex;
    updateAttackSimulationPanel();

    if (stepIndex < totalSteps - 1) {
      const shouldContinue = await waitForSimulationDelay(runToken, ATTACK_SIMULATION_STEP_DELAY_MS);
      if (!shouldContinue) {
        return;
      }
    }
  }

  if (attackSimulationState.runToken !== runToken) {
    return;
  }

  attackSimulationState.running = false;
  attackSimulationState.paused = false;
  attackSimulationState.stepIndex = totalSteps;
  updateAttackSimulationPanel();
}

function resetSimulation() {
  resetSimulationState();
}

async function loadRiskData() {
  if (cachedRiskAssets) {
    return cachedRiskAssets;
  }

  const res = await fetch(`${API_BASE_URL}/risk-score`, {
    method: "GET"
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }

  const data = await res.json();
  cachedRiskAssets = normalizeRiskAssets(data?.risk?.top_assets || []);
  window.latestRiskAssets = cachedRiskAssets;
  return cachedRiskAssets;
}

function getOrCreateGraphTooltip() {
  const graphContainer = document.getElementById("cy");
  if (!graphContainer) {
    return null;
  }

  let tooltip = document.getElementById("graph-risk-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.id = "graph-risk-tooltip";
    tooltip.className = "graph-risk-tooltip";
    graphContainer.appendChild(tooltip);
  }

  return tooltip;
}

function hideGraphTooltip() {
  const tooltip = document.getElementById("graph-risk-tooltip");
  if (!tooltip) {
    return;
  }

  tooltip.style.display = "none";
}

function showGraphTooltip(node, renderedPosition) {
  const tooltip = getOrCreateGraphTooltip();
  const graphContainer = document.getElementById("cy");
  if (!tooltip || !graphContainer || !renderedPosition) {
    return;
  }

  const label = String(node?.data("label") || node?.data("id") || "Asset");
  const riskText = node?.data("riskTooltip");
  tooltip.textContent = riskText || label;
  tooltip.style.display = "block";

  const offsetX = 12;
  const offsetY = 12;
  const maxLeft = Math.max(8, graphContainer.clientWidth - 180);
  const maxTop = Math.max(8, graphContainer.clientHeight - 40);

  tooltip.style.left = `${Math.min(renderedPosition.x + offsetX, maxLeft)}px`;
  tooltip.style.top = `${Math.min(renderedPosition.y + offsetY, maxTop)}px`;
}

function highlightRiskyNodes(assets) {
  const cy = window.cloudguardCy;
  const normalizedAssets = Array.isArray(assets) ? assets : [];

  if (!cy || normalizedAssets.length === 0) {
    return;
  }

  // Clear old highlights before applying the next view's risk state.
  resetHighlight();

  cy.nodes().forEach((node) => {
    const label = node.data("label") || node.data("id") || "";
    const normalizedLabel = normalize(label);

    if (!normalizedLabel) {
      return;
    }

    const riskMeta = normalizedAssets.find((item) => {
      const assetId = String(item?.id || "").trim();
      const assetName = normalize(item?.name);
      const nodeId = String(node.id() || "").trim();

      if (assetId && assetId === nodeId) {
        return true;
      }

      return assetName === normalizedLabel;
    });

    console.log("Node:", label, "→ Match:", riskMeta?.name);

    if (!riskMeta) {
      node.removeClass("high-risk medium-risk low-risk");
      return;
    }

    const level = riskMeta.risk_level;
    const riskDisplay = formatRiskValue(riskMeta.risk_score);

    if (level === "HIGH") {
      node.removeClass("medium-risk low-risk");
      node.addClass("high-risk");
    } else if (level === "MEDIUM") {
      node.removeClass("high-risk low-risk");
      node.addClass("medium-risk");
    } else {
      node.removeClass("high-risk medium-risk");
      node.addClass("low-risk");
    }

    if (node && !node.empty()) {
      node.data("riskTooltip", `${label} | Risk: ${riskDisplay} (${level})`);
    }
  });
}

function highlightRiskNodes() {
  highlightRiskyNodes(window.latestRiskAssets || []);
}

function updateHighRiskNodeIds(riskAssets) {
  const cy = window.cloudguardCy;
  const assets = Array.isArray(riskAssets) ? riskAssets : [];
  const idSet = new Set();
  const highRiskNames = new Set();

  assets.forEach((asset) => {
    const level = String(asset?.risk_level || "").toUpperCase();
    if (level !== "HIGH") {
      return;
    }

    const id = String(asset?.id || "").trim();
    if (id) {
      idSet.add(id);
    }

    const name = normalize(asset?.name || asset?.asset_name || asset?.asset || "");
    if (name) {
      highRiskNames.add(name);
    }
  });

  if (cy && highRiskNames.size > 0) {
    cy.nodes().forEach((node) => {
      const label = normalize(node.data("label") || node.data("id") || node.id());
      if (highRiskNames.has(label)) {
        idSet.add(String(node.id()));
      }
    });
  }

  highRiskNodeIds = Array.from(idSet);
}

function getRiskHighlightedNodeIds() {
  const cy = window.cloudguardCy;
  if (!cy) {
    return [];
  }

  return highRiskNodeIds.filter((nodeId) => {
    const node = cy.getElementById(String(nodeId || ""));
    return !!node && !node.empty();
  });
}

function findPredictionByNode(nodeId) {
  return currentPredictions.find((prediction) => String(prediction?.node || prediction?.id || "") === String(nodeId || ""));
}

function normalizePredictionLabel(prediction) {
  const label = String(prediction?.label || prediction?.risk_label || prediction?.level || "").trim().toUpperCase();

  if (label === "HIGH" || label === "MEDIUM" || label === "LOW") {
    return label;
  }

  const probability = Number(prediction?.probability || 0) * 100;
  if (probability > 70) {
    return "HIGH";
  }

  if (probability >= 40) {
    return "MEDIUM";
  }

  return "LOW";
}

function normalizePredictionTargets(targets) {
  if (Array.isArray(targets)) {
    return targets;
  }

  if (targets && typeof targets === "object") {
    return [targets];
  }

  return [];
}

function generateReasons(nodeId) {
  const reasons = [];
  const cy = window.cloudguardCy;
  if (!cy || !nodeId) {
    return ["Unknown risk factors"];
  }

  const node = cy.getElementById(String(nodeId));
  if (!node || node.empty()) {
    return ["Unknown risk factors"];
  }

  const data = node.data() || {};

  if (data.internet_exposed) reasons.push("Internet exposed");
  if (data.weak_iam) reasons.push("Weak IAM configuration");
  if (Number(data.vulnerability_count) > 5) reasons.push("Multiple vulnerabilities");
  if (Number(data.misconfiguration_count) > 0) reasons.push("Misconfigurations present");

  return reasons.length ? reasons : ["High attack path probability"];
}

function showNodeDetails(nodeData) {
  const detailsPanel = document.getElementById("graph-node-details");
  if (!detailsPanel) {
    return;
  }

  const assetId = nodeData?.id || "Unknown";
  const assetLabel = nodeData?.label || nodeData?.name || assetId || "Unknown";
  const assetType = nodeData?.type || "Unknown";
  const prediction = predictionMode ? (findPredictionByNode(assetId) || findPredictionByNode(assetLabel)) : null;

  const confidence = Number(prediction?.probability);
  const predictionMarkup = prediction
    ? `
      <p><strong>Prediction:</strong> ${prediction.label || "Unknown"}</p>
      <p><strong>Confidence:</strong> ${Number.isFinite(confidence) ? `${(confidence * 100).toFixed(1)}%` : "N/A"}</p>
    `
    : "";

  detailsPanel.innerHTML = `
    <h3>Asset Details</h3>
    <p><strong>ID:</strong> ${assetId}</p>
    <p><strong>Label:</strong> ${assetLabel}</p>
    <p><strong>Type:</strong> ${assetType}</p>
    ${predictionMarkup}
  `;
}

function getPredictionReasons(prediction) {
  if (Array.isArray(prediction?.reasons)) {
    return prediction.reasons.filter(Boolean).map(String);
  }

  if (typeof prediction?.reason === "string" && prediction.reason.trim()) {
    return [prediction.reason.trim()];
  }

  if (typeof prediction?.reason === "object" && prediction.reason) {
    return Object.values(prediction.reason)
      .flat()
      .filter(Boolean)
      .map(String);
  }

  return [];
}

function getPredictionBadgeClass(label) {
  const normalized = String(label || "").toLowerCase();

  if (normalized.includes("high")) {
    return "badge-high";
  }

  if (normalized.includes("medium")) {
    return "badge-medium";
  }

  if (normalized.includes("low")) {
    return "badge-low";
  }

  return "badge-medium";
}

function getRiskLabel(probability) {
  const value = Number(probability || 0);

  if (value >= 0.80) {
    return "HIGH";
  }

  if (value >= 0.65) {
    return "MEDIUM";
  }

  return "LOW";
}
function deduplicatePredictions(predictions) {
  const map = new Map();

  (Array.isArray(predictions) ? predictions : []).forEach((prediction) => {
    const nodeId = String(prediction?.node || prediction?.id || "").trim();
    if (!nodeId) {
      return;
    }

    if (!map.has(nodeId) || Number(map.get(nodeId)?.probability || 0) < Number(prediction?.probability || 0)) {
      map.set(nodeId, {
        ...prediction,
        node: nodeId
      });
    }
  });

  return Array.from(map.values());
}

function showNoPredictionsMessage() {
  renderAssetPredictionPanel({ predicted_next_target: null });
}

function focusRiskNode(assetName) {
  focusAndHighlightNodeByAssetName(assetName, true);
}

function renderPredictions(predictions) {
  if (!Array.isArray(predictions) || predictions.length === 0) {
    showNoPredictionsMessage();
    return;
  }

  const sortedPredictions = [...predictions].sort((left, right) => {
    const leftProbability = Number(left?.probability || 0);
    const rightProbability = Number(right?.probability || 0);
    return rightProbability - leftProbability;
  });

  const bestPrediction = sortedPredictions[0] || {};
  const predictedTarget = String(bestPrediction?.node || bestPrediction?.id || bestPrediction?.target || "Unknown node");
  const reasons = getPredictionReasons(bestPrediction).length > 0
    ? getPredictionReasons(bestPrediction)
    : generateReasons(predictedTarget);

  renderAssetPredictionPanel({
    predicted_next_target: {
      asset_name: predictedTarget,
      reason: reasons.join("; "),
      confidence: Number(bestPrediction?.probability || 0),
      impact_hint: null
    }
  });

  focusAndHighlightNodeByAssetName(predictedTarget, false);
  try {
    const sourceElem = findNodeByAssetName(getAssetAnalysisSourceName(currentAssetAnalysis || {}));
    const sourceId = sourceElem && !sourceElem.empty() ? String(sourceElem.id()) : null;
    let targetId = bestPrediction?.node ? String(bestPrediction.node) : null;
    if (!targetId) {
      const targetElem = findNodeByAssetName(predictedTarget);
      if (targetElem && !targetElem.empty()) targetId = String(targetElem.id());
    }

    if (sourceId && targetId) highlightPredictionPath(sourceId, targetId);
  } catch (e) {
    // ignore
  }
}

function applyPredictionHighlight(predictions) {
  const cy = window.cloudguardCy;
  if (!cy) {
    return;
  }

  const normalizedPredictions = Array.isArray(predictions) ? predictions : [];

  cy.batch(() => {
    cy.nodes().removeClass("predicted risk-predicted");

    normalizedPredictions.forEach((prediction) => {
      const nodeId = String(prediction?.node || prediction?.id || "").trim();
      if (!nodeId) {
        return;
      }

      const node = cy.getElementById(nodeId);
      if (!node || node.empty()) {
        return;
      }

      if (highRiskNodeIds.includes(nodeId)) {
        node.addClass("risk-predicted");
      } else {
        node.addClass("predicted");
      }
    });
  });
}

function applyCombinedHighlight(predictions, riskyNodes) {
  const cy = window.cloudguardCy;
  if (!cy || !Array.isArray(predictions) || !Array.isArray(riskyNodes)) {
    return;
  }

  const riskySet = new Set(riskyNodes.map((nodeId) => String(nodeId || "").trim()).filter(Boolean));

  cy.batch(() => {
    predictions.forEach((prediction) => {
      const nodeId = String(prediction?.node || prediction?.id || "").trim();
      if (!nodeId || !riskySet.has(nodeId)) {
        return;
      }

      const node = cy.getElementById(nodeId);
      if (!node || node.empty()) {
        return;
      }

      node.addClass("risk-predicted");
    });
  });
}

function highlightConnectedEdges(nodeId) {
  const cy = window.cloudguardCy;
  if (!cy || !nodeId) {
    return;
  }

  const node = cy.getElementById(nodeId);
  if (!node || node.empty()) {
    return;
  }

  cy.batch(() => {
    cy.edges().removeClass("highlighted");
    node.connectedEdges().addClass("highlighted");
  });
}

function focusNode(nodeId) {
  const cy = window.cloudguardCy;
  if (!cy || !nodeId) {
    return;
  }

  const node = cy.getElementById(nodeId);
  if (!node || node.empty()) {
    return;
  }

  cy.animate(
    {
      fit: {
        eles: node,
        padding: 50
      }
    },
    {
      duration: 500
    }
  );

  highlightConnectedEdges(nodeId);
  showNodeDetails(node.data());
}

function renderGraph(graphData) {
  const graph = graphData;
  const graphContainer = document.getElementById("cy");

  if (!graphContainer) {
    console.error("Graph container not found");
    return;
  }

  if (attackSimulationState.running || attackSimulationState.paused) {
    resetSimulationState();
  }

  resetHighlight();

  if (!graph || !Array.isArray(graph.nodes) || graph.nodes.length === 0) {
    console.warn("No graph data to render");
    return;
  }

  const edges = Array.isArray(graph.edges) ? graph.edges : [];

  const positionedNodes = graph.nodes.map((node, index) => ({
    ...node,
    position: {
      x: 100 + (index * 200),
      y: 200
    }
  }));

  const elements = [
    ...positionedNodes,
    ...edges
  ];

  if (window.cloudguardCy && typeof window.cloudguardCy.destroy === "function") {
    window.cloudguardCy.destroy();
    window.cloudguardCy = null;
  }

  const cy = cytoscape({
    container: graphContainer,
    elements: elements,

    style: [
      {
        selector: "node",
        style: {
          "background-color": "#4da3ff",
          "width": 54,
          "height": 54,
          "border-width": 2,
          "border-color": "#888",
          "label": "data(label)",
          "color": "#fff",
          "text-valign": "center",
          "text-halign": "center",
          "font-size": 11,
          "text-outline-width": 2,
          "text-outline-color": "#0f172a",
          "transition-property": "background-color, border-color, width, height, opacity, line-color, target-arrow-color",
          "transition-duration": "120ms"
        }
      },
      {
        selector: ".high-risk",
        style: {
          "background-color": "#ff4d4f",
          "border-color": "#ff4d4f",
          "border-width": 6,
          "overlay-color": "#ff4d4f",
          "overlay-opacity": 0.12,
          "background-opacity": 0.95
        }
      },
      {
        selector: ".medium-risk",
        style: {
          "background-color": "#ffcc00",
          "border-color": "#ffcc00",
          "border-width": 6,
          "overlay-color": "#ffcc00",
          "overlay-opacity": 0.1,
          "background-opacity": 0.92
        }
      },
      {
        selector: ".low-risk",
        style: {
          "background-color": "#3a7bd5",
          "border-color": "#52c41a",
          "border-width": 3,
          "overlay-opacity": 0,
          "background-opacity": 0.88
        }
      },
      {
        selector: "node[type = \"Internet\"]",
        style: {
          "background-color": "#ef4444",
          "border-color": "#fecaca"
        }
      },
      {
        selector: "node[type = \"VM\"], node[type = \"Server\"]",
        style: {
          "background-color": "#3b82f6",
          "border-color": "#bfdbfe"
        }
      },
      {
        selector: "node[type = \"Database\"]",
        style: {
          "background-color": "#8b5cf6",
          "border-color": "#e9d5ff"
        }
      },
      {
        selector: "edge",
        style: {
          "width": 3.5,
          "line-color": "#6b7280",
          "target-arrow-color": "#6b7280",
          "target-arrow-shape": "triangle",
          "arrow-scale": 1.15,
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": "8px",
          "color": "#cbd5e1",
          "text-background-color": "#0f172a",
          "text-background-opacity": 0.85,
          "text-background-padding": 2,
          "transition-property": "line-color, target-arrow-color, width, opacity",
          "transition-duration": "120ms"
        }
      },
      {
        selector: "edge[label = \"EXPOSED_TO\"]",
        style: {
          "line-color": "#ef4444",
          "target-arrow-color": "#ef4444"
        }
      },
      {
        selector: "edge[label = \"CONNECTS_TO\"]",
        style: {
          "line-color": "#22c55e",
          "target-arrow-color": "#22c55e"
        }
      },
      {
        selector: ".dimmed",
        style: {
          opacity: 0.18
        }
      },
      {
        selector: ".graph-search-dimmed",
        style: {
          opacity: 0.14
        }
      },
      {
        selector: ".graph-search-match",
        style: {
          "background-color": "#22d3ee",
          "border-color": "#a5f3fc",
          "border-width": 7,
          "overlay-color": "#22d3ee",
          "overlay-opacity": 0.18,
          "shadow-blur": 24,
          "shadow-color": "#67e8f9",
          "shadow-opacity": 0.62,
          opacity: 1,
          "z-index": 16
        }
      },
      {
        selector: ".graph-search-edge",
        style: {
          width: 5.5,
          "line-color": "#22d3ee",
          "target-arrow-color": "#22d3ee",
          opacity: 1
        }
      },
      {
        selector: ".selected",
        style: {
          "background-color": "#facc15",
          "border-color": "#fde68a",
          "border-width": 5,
          width: 66,
          height: 66,
          "z-index": 10
        }
      },
      {
        selector: ".neighbor",
        style: {
          opacity: 1,
          "border-color": "#fbbf24",
          "border-width": 4
        }
      },
      {
        selector: ".hovered",
        style: {
          width: 68,
          height: 68,
          "border-width": 4,
          "border-color": "#ffffff",
          "z-index": 12
        }
      },
      {
        selector: ".highlighted-edge",
        style: {
          width: 5,
          "line-color": "#facc15",
          "target-arrow-color": "#facc15",
          opacity: 1
        }
      },
      {
        selector: ".predicted",
        style: {
          "background-color": "#FFA500",
          "border-width": 3,
          "border-color": "#FF4500",
          "overlay-color": "#FF8C00",
          "overlay-opacity": 0.14,
          "background-opacity": 0.92,
          "transition-property": "background-color, border-color, border-width, overlay-opacity, background-opacity",
          "transition-duration": "180ms"
        }
      },
      {
        selector: ".risk-predicted",
        style: {
          "background-color": "#FF00FF",
          "border-width": 4,
          "border-color": "#ff66ff",
          "overlay-color": "#FF00FF",
          "overlay-opacity": 0.18,
          "background-opacity": 0.9
        }
      },
      {
        selector: ".predicted-focus",
        style: {
          "border-width": 7,
          "border-color": "#ffd166",
          "overlay-color": "#ffd166",
          "overlay-opacity": 0.2,
          "shadow-blur": 28,
          "shadow-color": "#ffd166",
          "shadow-opacity": 0.55
        }
      },
      {
        selector: ".analysis-primary-target",
        style: {
          "background-color": "#ff9f1a",
          "border-width": 8,
          "border-color": "#ffb347",
          "overlay-color": "#ff9f1a",
          "overlay-opacity": 0.22,
          "shadow-blur": 34,
          "shadow-color": "#ffb347",
          "shadow-opacity": 0.72,
          "background-opacity": 0.98,
          "z-index": 13
        }
      },
      {
        selector: ".analysis-source-node",
        style: {
          "border-width": 5,
          "border-color": "#8be9fd",
          "overlay-color": "#8be9fd",
          "overlay-opacity": 0.12,
          "shadow-blur": 18,
          "shadow-color": "#8be9fd",
          "shadow-opacity": 0.45
        }
      },
      {
        selector: ".analysis-path-node",
        style: {
          "border-width": 4,
          "border-color": "#f0b85f",
          "overlay-color": "#f0b85f",
          "overlay-opacity": 0.08
        }
      },
      {
        selector: ".analysis-path-edge",
        style: {
          width: 5.8,
          "line-color": "#22c55e",
          "target-arrow-color": "#22c55e",
          opacity: 1
        }
      },
      {
        selector: ".prediction-source",
        style: {
          "border-width": 6,
          "border-color": "#3b82f6",
          "overlay-color": "#3b82f6",
          "overlay-opacity": 0.18,
          "shadow-blur": 26,
          "shadow-color": "#60a5fa",
          "shadow-opacity": 0.6
        }
      },
      {
        selector: ".prediction-target",
        style: {
          "border-width": 6,
          "border-color": "#ff8c00",
          "overlay-color": "#ff8c00",
          "overlay-opacity": 0.22,
          "shadow-blur": 28,
          "shadow-color": "#ffb347",
          "shadow-opacity": 0.7,
          "background-opacity": 0.98,
          "z-index": 15
        }
      },
      {
        selector: ".prediction-edge",
        style: {
          "width": 6,
          "line-color": "#60a5fa",
          "target-arrow-color": "#60a5fa",
          opacity: 1
        }
      },
      {
        selector: ".hover-highlighted-edge",
        style: {
          width: 4.5,
          "line-color": "#60a5fa",
          "target-arrow-color": "#60a5fa",
          opacity: 1
        }
      },
      {
        selector: ".pulse",
        style: {
          "background-color": "#00ffcc",
          "border-color": "#a7f3d0"
        }
      },
      {
        selector: ".sim-visited",
        style: {
          opacity: 0.42,
          "background-color": "#7c3aed",
          "border-color": "#c4b5fd",
          "border-width": 3,
          "background-opacity": 0.8
        }
      },
      {
        selector: ".sim-active",
        style: {
          "background-color": "#ff6b1a",
          "border-color": "#ffd166",
          "border-width": 8,
          "overlay-color": "#ff6b1a",
          "overlay-opacity": 0.22,
          "shadow-blur": 30,
          "shadow-color": "#ffd166",
          "shadow-opacity": 0.75,
          opacity: 1,
          "z-index": 14
        }
      },
      {
        selector: ".sim-visited-edge",
        style: {
          width: 4,
          opacity: 0.48,
          "line-color": "#7c8aa3",
          "target-arrow-color": "#7c8aa3"
        }
      },
      {
        selector: ".sim-active-edge",
        style: {
          width: 6,
          opacity: 1,
          "line-color": "#ffb347",
          "target-arrow-color": "#ffb347",
          "shadow-blur": 10,
          "shadow-color": "#ffb347",
          "shadow-opacity": 0.65
        }
      }
    ],

    layout: {
      name: "breadthfirst",
      directed: true,
      spacingFactor: 1.5
    }
  });

  if (!cy) {
    return;
  }

  window.cloudguardCy = cy;
  document.querySelector(".graph-placeholder")?.remove();

  cy.ready(() => {
    resetHighlight();
    if (riskMode) {
      highlightRiskyNodes(window.latestRiskAssets || []);
    }

    updateHighRiskNodeIds(window.latestRiskAssets || []);

    if (predictionMode && currentPredictions.length > 0) {
      applyPredictionHighlight(currentPredictions);
    }

    if (riskMode && predictionMode && currentPredictions.length > 0) {
      applyCombinedHighlight(currentPredictions, getRiskHighlightedNodeIds());
    }

    if (currentAssetAnalysis) {
      highlightPredictedTargetInGraph(currentAssetAnalysis);
    }

    const graphSearchInput = document.getElementById("graph-search-input");
    const graphSearchValue = String(graphSearchInput?.value || "").trim();
    if (graphSearchValue) {
      searchGraphAsset(graphSearchValue, { focus: false, announce: false });
    }

    updateAttackSimulationPanel();
  });


  const clearHoverState = () => {
    cy.batch(() => {
      cy.nodes().removeClass("hovered");
      cy.edges().removeClass("hover-highlighted-edge");
    });
  };

  const clearSelectionState = () => {
    cy.batch(() => {
      cy.elements().removeClass("selected neighbor dimmed highlighted-edge");
    });
  };

  const applySelectionState = (node) => {
    const selectedNeighborhood = node.closedNeighborhood();
    const selectedNodes = selectedNeighborhood.nodes();
    const selectedEdges = node.connectedEdges();

    cy.batch(() => {
      cy.elements().removeClass("selected neighbor dimmed highlighted-edge");
      cy.nodes().addClass("dimmed");
      cy.edges().addClass("dimmed");
      selectedNodes.removeClass("dimmed");
      selectedEdges.removeClass("dimmed");
      node.addClass("selected");
      selectedNodes.not(node).addClass("neighbor");
      selectedEdges.addClass("highlighted-edge");
    });
  };

  cy.on("mouseover", "node", function (evt) {
    const node = evt.target;

    cy.batch(() => {
      node.addClass("hovered");
      node.connectedEdges().addClass("hover-highlighted-edge");
    });

    showGraphTooltip(node, evt.renderedPosition);
  });

  cy.on("mousemove", "node", function (evt) {
    showGraphTooltip(evt.target, evt.renderedPosition);
  });

  cy.on("mouseout", "node", function (evt) {
    const node = evt.target;

    cy.batch(() => {
      node.removeClass("hovered");
      node.connectedEdges().removeClass("hover-highlighted-edge");
    });

    hideGraphTooltip();
  });

  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    const nodeData = node.data();

    applySelectionState(node);

    cy.animate(
      {
        center: { eles: node },
        zoom: 1.35
      },
      {
        duration: 300
      }
    );

    showNodeDetails(nodeData);
  });

  // Subtle, non-blocking attack path pulse based on returned node order.
  graph.nodes.forEach((graphNode, index) => {
    const nodeId = graphNode?.data?.id;
    if (!nodeId) {
      return;
    }

    setTimeout(() => {
      if (!window.cloudguardCy) {
        return;
      }

      const cyNode = cy.getElementById(nodeId);
      if (!cyNode || cyNode.empty()) {
        return;
      }

      cyNode.addClass("pulse");

      setTimeout(() => {
        cyNode.removeClass("pulse");
      }, 220);
    }, index * 240);
  });
}

async function fetchAttackPath() {
  updateStatus("Loading attack path...", "loading");

  try {
    const response = await fetch(`${API_BASE_URL}/attack-path?start=Internet&target=Database%20Server`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    window.latestAttackPathData = data;
    currentGraphData = data.graph;
    riskMode = false;
    console.log("Attack Path:", data);

    renderGraph(currentGraphData);

    setLoadedAttackPathSimulation(data);

    updateStatus("Attack path loaded successfully", "success");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load attack path", "error");
  }
}

async function fetchAllPaths() {
  updateStatus("Loading all paths...", "loading");

  try {
    const response = await fetch(`${API_BASE_URL}/all-paths?start=Internet&target=Database%20Server`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    window.latestAllPathsData = data;
    currentGraphData = data.graph;
    riskMode = false;
    clearLoadedAttackPathSimulation();
    console.log("All Paths:", data);

    renderGraph(currentGraphData);

    updateStatus("All paths loaded successfully", "success");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load all paths", "error");
  }
}

async function fetchRiskScore() {
  cachedRiskAssets = null;
  await refreshRelatedHighRiskAssets({ silent: false });
}

async function refreshRelatedHighRiskAssets(options = {}) {
  const { silent = false } = options;

  if (!silent) {
    updateStatus("Loading risk score...", "loading");
  }

  try {
    const normalizedAssets = await loadRiskData();

    window.latestRiskAssets = normalizedAssets;
    cachedRiskAssets = normalizedAssets;
    updateHighRiskNodeIds(normalizedAssets);
    window.latestRiskSummary = {
      assetRiskByName: normalizedAssets.reduce((accumulator, asset) => {
        accumulator[asset.name] = {
          level: asset.risk_level,
          risk: asset.risk_score,
          reason: asset.reason
        };
        return accumulator;
      }, {})
    };

    riskMode = true;
    if (currentGraphData) {
      renderGraph(currentGraphData);
    }

    renderRelatedHighRiskAssets(normalizedAssets);

    if (!silent) {
      updateStatus("Risk score loaded", "success");
    }
  } catch (error) {
    console.error(error);
    renderRelatedHighRiskAssets([]);
    if (!silent) {
      updateStatus("Failed to load risk score", "error");
    }
  }
}

async function fetchPrediction(inputData) {
  const response = await fetch(`${API_BASE_URL}/predict-compromise`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(inputData)
  });

  return await response.json();
}

async function handlePrediction(inputData = {}) {
  updateStatus("Loading predictions...", "loading");

  try {
    const cy = window.cloudguardCy;
    if (!cy || highRiskNodeIds.length === 0) {
      console.warn("Prediction skipped: missing graph or risk data");
      updateStatus("Prediction skipped: load graph and risk data first", "error");
      return;
    }

    predictionMode = true;
    const payload = {
      asset_type: "Database Server",
      internet_exposed: 1,
      public_access: 1,
      has_critical_data: 1,
      weak_iam: 1,
      lateral_movement_possible: 1,
      privilege_escalation_possible: 1,
      open_port_count: 14,
      vulnerability_count: 22,
      critical_vulnerability_count: 6,
      misconfiguration_count: 9,
      attack_path_count: 4,
      shortest_path_length: 2,
      exposure_score: 0.82,
      identity_risk_score: 0.73,
      network_risk_score: 0.69
    };

    console.log("Prediction request payload:", payload);

    const data = await fetchPrediction(payload);
    console.log("Prediction response:", data);

    const predictions = data.next_targets || [];

    if (predictions.length === 0) {
      showNoPredictionsMessage();
      return;
    }

    currentPredictions = predictions;
    renderPredictions(predictions);
    applyPredictionHighlight(predictions);

    // Render explainability panel using available asset analysis and best prediction
    try {
      const sorted = [...predictions].sort((a, b) => Number(b?.probability || 0) - Number(a?.probability || 0));
      const best = sorted[0] || null;
      renderExplainabilityPanel(currentAssetAnalysis, best);
    } catch (e) {
      // ignore
    }

    if (riskMode) {
      applyCombinedHighlight(predictions, getRiskHighlightedNodeIds());
    }

    updateStatus("Predictions loaded", "success");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load predictions", "error");
  }
}

function initGraph() {
  const graphContainer = document.getElementById("cy");

  if (!graphContainer) {
    console.error("Graph container not found");
    return;
  }
}

function zoomIn() {
  const cy = window.cloudguardCy;
  if (!cy) return;
  cy.zoom(cy.zoom() * 1.2);
}

function zoomOut() {
  const cy = window.cloudguardCy;
  if (!cy) return;
  cy.zoom(cy.zoom() * 0.8);
}

function fitGraph() {
  const cy = window.cloudguardCy;
  if (!cy) return;
  cy.fit(undefined, 40);
}

function resetGraph() {
  const cy = window.cloudguardCy;
  if (!cy) return;
  clearGraphSearchHighlight();
  cy.zoom(1);
  cy.center();
}

async function applyScenarioPreset(presetId) {
  const preset = scenarioPresets[presetId];
  if (!preset) {
    updateStatus("Unknown scenario preset", "error");
    return;
  }

  const assetName = normalizeAssetName(preset.assetName);
  selectedAssetName = assetName;

  const assetInput = document.getElementById("asset-selector-input");
  const graphSearchInput = document.getElementById("graph-search-input");
  if (assetInput) {
    assetInput.value = assetName;
  }
  if (graphSearchInput) {
    graphSearchInput.value = assetName;
  }

  updateStatus(preset.status, "loading");

  if (preset.graphMode === "risk-score") {
    if (!currentGraphData) {
      await fetchAttackPath();
    }
    await fetchRiskScore();
  } else {
    await fetchAttackPath();
  }

  await fetchAssetAnalysis(assetName);
  searchGraphAsset(assetName, { focus: true, announce: false });
  updateStatus(preset.status, "success");
}

document.addEventListener("DOMContentLoaded", () => {
  initGraph();

  document.getElementById("zoom-in")?.addEventListener("click", zoomIn);
  document.getElementById("zoom-out")?.addEventListener("click", zoomOut);
  document.getElementById("fit-graph")?.addEventListener("click", fitGraph);
  document.getElementById("reset-graph")?.addEventListener("click", resetGraph);
  document.getElementById("simulate-attack-button")?.addEventListener("click", startSimulation);
  document.getElementById("pause-simulation-button")?.addEventListener("click", pauseSimulation);
  document.getElementById("resume-simulation-button")?.addEventListener("click", resumeSimulation);
  document.getElementById("reset-simulation-button")?.addEventListener("click", resetSimulation);
  document.getElementById("graph-search-button")?.addEventListener("click", () => {
    searchGraphAsset(document.getElementById("graph-search-input")?.value || "");
  });
  document.getElementById("graph-search-clear")?.addEventListener("click", () => {
    const graphSearchInput = document.getElementById("graph-search-input");
    if (graphSearchInput) {
      graphSearchInput.value = "";
    }
    clearGraphSearchHighlight();
    updateStatus("Graph search cleared", "success");
  });
  document.getElementById("graph-search-input")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      searchGraphAsset(event.currentTarget.value);
    }
    if (event.key === "Escape") {
      event.currentTarget.value = "";
      clearGraphSearchHighlight();
      updateStatus("Graph search cleared", "success");
    }
  });
  document.querySelectorAll("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => applyScenarioPreset(button.getAttribute("data-preset")));
  });

  updateStatus(`Frontend ready. API base URL: ${API_BASE_URL}`);

  document.getElementById("btnAttackPath")?.addEventListener("click", fetchAttackPath);
  document.getElementById("btnAllPaths")?.addEventListener("click", fetchAllPaths);
  document.getElementById("btnRiskScore")?.addEventListener("click", fetchRiskScore);
  document.getElementById("btnPredictCompromise")?.addEventListener("click", () => handlePrediction());

  const assetForm = document.getElementById("asset-analysis-form");
  const assetInput = document.getElementById("asset-selector-input");
  const copyButton = document.getElementById("copy-recommendations-btn");

  document.getElementById("btnAssetAnalysis")?.addEventListener("click", () => {
    const requestedAsset = String(assetInput?.value || selectedAssetName || DEFAULT_ASSET_NAME).trim() || DEFAULT_ASSET_NAME;
    fetchAssetAnalysis(requestedAsset);
  });

  assetForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    const requestedAsset = String(assetInput?.value || "").trim() || DEFAULT_ASSET_NAME;
    fetchAssetAnalysis(requestedAsset);
  });

  assetInput?.addEventListener("change", () => {
    const requestedAsset = String(assetInput.value || "").trim() || DEFAULT_ASSET_NAME;
    fetchAssetAnalysis(requestedAsset);
  });

  copyButton?.addEventListener("click", copyRecommendationsToClipboard);
  document.getElementById("export-analysis-btn")?.addEventListener("click", exportCurrentAnalysis);

  updateAttackSimulationPanel();

  fetchAssetAnalysis(DEFAULT_ASSET_NAME);
  refreshRelatedHighRiskAssets({ silent: true });
});
