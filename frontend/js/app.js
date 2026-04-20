const API_BASE_URL = "http://localhost:8000";
let cachedRiskAssets = null;
let riskMode = false;
let predictionMode = false;
let currentPredictions = [];
let currentGraphData = null;
let highRiskNodeIds = [];

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

  window.cloudguardCy.nodes().removeClass("predicted risk-predicted");
  window.cloudguardCy.edges().removeClass("highlighted");
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
  const assetDetailsPanel = document.querySelector('[aria-label="Asset details panel"]');
  if (!assetDetailsPanel) {
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

  assetDetailsPanel.innerHTML = `
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
  const container = document.getElementById("prediction-list");
  if (!container) {
    return;
  }

  container.innerHTML = `<div class="prediction-empty">No predictions available</div>`;
}

function focusRiskNode(assetName) {
  const cy = window.cloudguardCy;
  if (!cy || !assetName) {
    return;
  }

  const targetNode = cy.nodes().filter((node) => {
    const label = String(node.data("label") || node.data("id") || "").trim();
    return label === assetName;
  }).first();

  if (!targetNode || targetNode.empty()) {
    return;
  }

  cy.elements().unselect();
  targetNode.select();
  cy.center(targetNode);
  cy.animate(
    {
      fit: {
        eles: targetNode,
        padding: 60
      }
    },
    {
      duration: 350
    }
  );

  showNodeDetails({
    id: targetNode.data("id") || assetName,
    label: targetNode.data("label") || assetName,
    type: targetNode.data("type") || "Unknown"
  });
}

function renderPredictions(predictions) {
  const container = document.getElementById("prediction-list");
  if (!container) {
    return;
  }

  container.innerHTML = "";

  if (!Array.isArray(predictions) || predictions.length === 0) {
    container.innerHTML = `<div class="prediction-empty">No predictions available</div>`;
    return;
  }

  const sortedPredictions = [...predictions].sort((left, right) => {
    const leftProbability = Number(left?.probability || 0);
    const rightProbability = Number(right?.probability || 0);
    return rightProbability - leftProbability;
  });

  sortedPredictions.forEach((prediction) => {
    const probability = Number(prediction?.probability || 0);
    const safeProbability = Number.isFinite(probability) ? Math.max(0, Math.min(1, probability)) : 0;
    const nodeName = String(prediction?.node || prediction?.id || prediction?.target || "Unknown node");
    const reasons = getPredictionReasons(prediction).length > 0 ? getPredictionReasons(prediction) : generateReasons(nodeName);
    const label = normalizePredictionLabel(prediction);
    const item = document.createElement("button");
    item.type = "button";
    item.classList.add("prediction-item");
    item.innerHTML = `
      <div class="prediction-item-row">
        <span class="prediction-dot predicted"></span>
        <strong>${nodeName}</strong>
        <span class="badge ${getPredictionBadgeClass(label)}">${label}</span>
      </div>
      <div class="prediction-confidence">Confidence: ${(safeProbability * 100).toFixed(1)}%</div>
      <div class="prediction-bar-track">
        <div class="prediction-bar-fill" style="width: ${safeProbability * 100}%"></div>
      </div>
      <div class="prediction-reason">${reasons.map((reason) => `• ${reason}`).join("<br />")}</div>
    `;

    item.addEventListener("click", () => {
      const targetNode = String(prediction?.node || prediction?.id || "");
      focusNode(targetNode);
      highlightConnectedEdges(targetNode);
    });

    container.appendChild(item);
  });
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

    const mitigations = Array.isArray(data.mitigations) ? data.mitigations : [];
    const mitigationPanel = document.querySelector('[aria-label="Mitigation suggestions panel"]');

    if (mitigationPanel) {
      if (mitigations.length === 0) {
        mitigationPanel.innerHTML = `
          <h3>Mitigation Suggestions</h3>
          <p>No mitigation suggestions available</p>
        `;
      } else {
        const mitigationItems = mitigations
          .map((item) => `<li>${item}</li>`)
          .join("");

        mitigationPanel.innerHTML = `
          <h3>Mitigation Suggestions</h3>
          <ul>${mitigationItems}</ul>
        `;
      }
    }

    renderGraph(currentGraphData);

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
    console.log("All Paths:", data);

    renderGraph(currentGraphData);

    updateStatus("All paths loaded successfully", "success");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load all paths", "error");
  }
}

async function fetchRiskScore() {
  updateStatus("Loading risk score...", "loading");
  const riskDashboardPanel = document.querySelector('[aria-label="Risk dashboard panel"]');

  try {
    const response = await fetch(`${API_BASE_URL}/risk-score`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    console.log("Risk score response:", data);

    const topAssets = Array.isArray(data?.risk?.top_assets) ? data.risk.top_assets : [];
    const normalizedAssets = normalizeRiskAssets(topAssets);
    const validRiskValues = normalizedAssets
      .map((asset) => asset.risk_score)
      .filter((risk) => Number.isFinite(risk));

    const avgRisk = validRiskValues.length === 0
      ? null
      : validRiskValues.reduce((sum, risk) => sum + risk, 0) / validRiskValues.length;
    const overallRiskValue = formatRiskValue(avgRisk);
    const overallRiskLevel = getRiskLevel(avgRisk);

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

    if (riskDashboardPanel) {
      riskDashboardPanel.innerHTML = "";

      if (normalizedAssets.length === 0) {
        riskDashboardPanel.innerHTML = `
          <h2>Risk Dashboard</h2>
          <p class="risk-overall">Overall Risk: ${overallRiskValue} <span class="badge ${getRiskBadgeClass(overallRiskLevel)}">${overallRiskLevel}</span></p>
          <p class="risk-summary">${getRiskSummaryMessage(overallRiskLevel)}</p>
          <p>No risk assets found</p>
        `;
      } else {
        const assetItems = normalizedAssets
          .map((asset) => {
            return `
              <article class="risk-card ${asset.risk_level.toLowerCase()}" data-asset-name="${asset.name}">
                <div class="risk-title">${asset.name} <span class="badge ${getRiskBadgeClass(asset.risk_level)}">${asset.risk_level}</span></div>
                <div class="risk-score">Risk Score: ${formatRiskValue(asset.risk_score)}</div>
                <div class="risk-reason">Reason: ${asset.reason}</div>
              </article>
            `;
          })
          .join("");

        riskDashboardPanel.innerHTML = `
          <h2>Risk Dashboard</h2>
          <p class="risk-overall">Overall Risk: ${overallRiskValue} <span class="badge ${getRiskBadgeClass(overallRiskLevel)}">${overallRiskLevel}</span></p>
          <p class="risk-summary">${getRiskSummaryMessage(overallRiskLevel)}</p>
          <div class="risk-grid">${assetItems}</div>
        `;

        riskDashboardPanel.querySelectorAll(".risk-card").forEach((card) => {
          card.addEventListener("click", () => {
            const assetName = card.getAttribute("data-asset-name");
            focusRiskNode(assetName || "");
          });
        });
      }
    }

    updateStatus("Risk score loaded", "success");
  } catch (error) {
    console.error(error);
    if (riskDashboardPanel) {
      riskDashboardPanel.innerHTML = `
        <h2>Risk Dashboard</h2>
        <p>Failed to load risk data</p>
      `;
    }
    updateStatus("Failed to load risk score", "error");
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
  cy.zoom(1);
  cy.center();
}

document.addEventListener("DOMContentLoaded", () => {
  initGraph();

  document.getElementById("zoom-in")?.addEventListener("click", zoomIn);
  document.getElementById("zoom-out")?.addEventListener("click", zoomOut);
  document.getElementById("fit-graph")?.addEventListener("click", fitGraph);
  document.getElementById("reset-graph")?.addEventListener("click", resetGraph);

  updateStatus(`Frontend ready. API base URL: ${API_BASE_URL}`);

  document.getElementById("btnAttackPath")?.addEventListener("click", fetchAttackPath);
  document.getElementById("btnAllPaths")?.addEventListener("click", fetchAllPaths);
  document.getElementById("btnRiskScore")?.addEventListener("click", fetchRiskScore);
  document.getElementById("btnPredictCompromise")?.addEventListener("click", () => handlePrediction());
});
