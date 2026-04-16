const API_BASE_URL = "http://localhost:8000";

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

function renderGraph(data) {
  const graph = data.graph;
  const graphContainer = document.getElementById("cy");

  if (!graphContainer) {
    console.error("Graph container not found");
    return;
  }

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
  }

  const cy = cytoscape({
    container: graphContainer,
    elements: elements,

    style: [
      {
        selector: "node",
        style: {
          "background-color": "#4da6ff",
          "width": 54,
          "height": 54,
          "border-width": 3,
          "border-color": "#dbeafe",
          "shadow-blur": 12,
          "shadow-color": "#4da6ff",
          "shadow-opacity": 0.35,
          "shadow-offset-x": 0,
          "shadow-offset-y": 0,
          "label": "data(label)",
          "color": "#fff",
          "text-valign": "center",
          "text-halign": "center",
          "font-size": "10px",
          "text-outline-width": 2,
          "text-outline-color": "#0f172a",
          "transition-property": "background-color, border-color, width, height, opacity, line-color, target-arrow-color",
          "transition-duration": "120ms"
        }
      },
      {
        selector: "node[type = \"Internet\"]",
        style: {
          "background-color": "#ef4444",
          "border-color": "#fecaca",
          "shadow-color": "#ef4444"
        }
      },
      {
        selector: "node[type = \"VM\"], node[type = \"Server\"]",
        style: {
          "background-color": "#3b82f6",
          "border-color": "#bfdbfe",
          "shadow-color": "#3b82f6"
        }
      },
      {
        selector: "node[type = \"Database\"]",
        style: {
          "background-color": "#8b5cf6",
          "border-color": "#e9d5ff",
          "shadow-color": "#8b5cf6"
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
          "shadow-blur": 18,
          "shadow-color": "#facc15",
          "shadow-opacity": 0.75,
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
          "shadow-blur": 18,
          "shadow-opacity": 0.8,
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
          "border-color": "#a7f3d0",
          "shadow-color": "#00ffcc",
          "shadow-opacity": 0.75,
          "shadow-blur": 16
        }
      }
    ],

    layout: {
      name: "preset"
    }
  });

  if (!cy) {
    return;
  }

  window.cloudguardCy = cy;
  document.querySelector(".graph-placeholder")?.remove();


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
  });

  cy.on("mouseout", "node", function (evt) {
    const node = evt.target;

    cy.batch(() => {
      node.removeClass("hovered");
      node.connectedEdges().removeClass("hover-highlighted-edge");
    });
  });

  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    const nodeData = node.data();
    const assetDetailsPanel = document.querySelector('[aria-label="Asset details panel"]');

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

    if (!assetDetailsPanel) {
      return;
    }

    const assetLabel = nodeData.label || nodeData.id || "Unknown";
    const assetId = nodeData.id || "Unknown";
    const assetType = nodeData.type || "Unknown";

    assetDetailsPanel.innerHTML = `
      <h3>Asset Details</h3>
      <p><strong>ID:</strong> ${assetId}</p>
      <p><strong>Label:</strong> ${assetLabel}</p>
      <p><strong>Type:</strong> ${assetType}</p>
    `;
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
    console.log("Attack path response:", data);

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

    renderGraph(data);

    updateStatus("Attack path loaded successfully", "success");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load attack path", "error");
  }
}

async function fetchRiskScore() {
  updateStatus("Loading risk score...", "loading");

  try {
    const response = await fetch(`${API_BASE_URL}/risk-score`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    console.log("Risk score response:", data);

    const topAssets = data.risk?.top_assets || [];
    const riskDashboardPanel = document.querySelector('[aria-label="Risk dashboard panel"]');

    if (riskDashboardPanel) {
      if (topAssets.length === 0) {
        riskDashboardPanel.innerHTML = `
          <h3>Top Risk Assets</h3>
          <p>No high risk assets found</p>
        `;
      } else {
        const assetItems = topAssets
          .map((asset) => {
            const name = asset.asset || asset.name || "Unknown";
            const score = asset.risk_score || asset.score || "N/A";
            return `<li>${name} (Risk: ${score})</li>`;
          })
          .join("");

        riskDashboardPanel.innerHTML = `
          <h3>Top Risk Assets</h3>
          <ul>${assetItems}</ul>
        `;
      }
    }

    updateStatus("Risk score loaded", "success");
  } catch (error) {
    console.error(error);
    updateStatus("Failed to load risk score", "error");
  }
}

async function fetchPrediction() {
  updateStatus("Loading predictions...", "loading");

  try {
    const response = await fetch(`${API_BASE_URL}/predict-compromise`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        asset_type: "VM",
        internet_exposed: 1,
        public_access: 1,
        has_critical_data: 1,
        weak_iam: 1,
        lateral_movement_possible: 1,
        privilege_escalation_possible: 1,
        open_port_count: 5,
        vulnerability_count: 10,
        critical_vulnerability_count: 3,
        misconfiguration_count: 2,
        attack_path_count: 1,
        shortest_path_length: 3,
        exposure_score: 80,
        identity_risk_score: 70,
        network_risk_score: 75
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    console.log("Prediction response:", data);

    const panel = document.querySelector('[aria-label="Prediction panel"]');
    if (!panel) {
      return;
    }

    if (!data.predicted_label) {
      panel.innerHTML = `
        <h3>Predicted Risk Level</h3>
        <p>No prediction available</p>
      `;
      return;
    }

    const label = data.predicted_label;
    let color = "#4caf50";

    if (label === "HIGH") color = "#ff4d4f";
    if (label === "MEDIUM") color = "#faad14";

    panel.innerHTML = `
      <h3>Predicted Risk Level</h3>
      <p style="color:${color}; font-weight:bold;">
        ${label}
      </p>
    `;

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

  const sidebarButtons = document.querySelectorAll(".sidebar button");
  const attackPathItem = Array.from(sidebarButtons).find(
    (button) => button.textContent?.trim() === "/attack-path"
  );

  if (attackPathItem) {
    attackPathItem.addEventListener("click", fetchAttackPath);
  }

  const riskScoreItem = Array.from(sidebarButtons).find(
    (button) => button.textContent?.trim() === "/risk-score"
  );

  if (riskScoreItem) {
    riskScoreItem.addEventListener("click", fetchRiskScore);
  }

  const predictCompromiseItem = Array.from(sidebarButtons).find(
    (button) => button.textContent?.trim() === "/predict-compromise"
  );

  if (predictCompromiseItem) {
    predictCompromiseItem.addEventListener("click", fetchPrediction);
  }
});
