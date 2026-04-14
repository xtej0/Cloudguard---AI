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

  const elements = [
    ...graph.nodes,
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
          "width": 42,
          "height": 42,
          "border-width": 2,
          "border-color": "#ffffff",
          "shadow-blur": 14,
          "shadow-color": "#4da6ff",
          "shadow-opacity": 0.45,
          "shadow-offset-x": 0,
          "shadow-offset-y": 0,
          "label": "data(label)",
          "color": "#fff",
          "text-valign": "center",
          "text-halign": "center",
          "font-size": "10px"
        }
      },
      {
        selector: "edge",
        style: {
          "width": 3,
          "line-color": "#00ffcc",
          "target-arrow-color": "#00ffcc",
          "target-arrow-shape": "triangle",
          "arrow-scale": 1.25,
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": "8px",
          "color": "#ccc"
        }
      }
    ],

    layout: {
      name: "breadthfirst",
      directed: true,
      padding: 10
    }
  });

  if (!cy) {
    return;
  }

  const defaultNodeStyle = {
    backgroundColor: "#4da6ff",
    borderWidth: 2,
    borderColor: "#ffffff",
    shadowColor: "#4da6ff",
    shadowOpacity: 0.45
  };
  const selectedNodeStyle = {
    backgroundColor: "#ffcc00",
    borderWidth: 4,
    borderColor: "#ffe49b",
    shadowColor: "#ffcc00",
    shadowOpacity: 0.65
  };
  let selectedNodeId = null;

  window.cloudguardCy = cy;
  document.querySelector(".graph-placeholder")?.remove();

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

      cyNode.style({
        "background-color": "#00ffcc",
        "shadow-color": "#00ffcc",
        "shadow-opacity": 0.75
      });

      setTimeout(() => {
        const isSelected = selectedNodeId === nodeId;
        cyNode.style({
          "background-color": isSelected ? selectedNodeStyle.backgroundColor : defaultNodeStyle.backgroundColor,
          "border-width": isSelected ? selectedNodeStyle.borderWidth : defaultNodeStyle.borderWidth,
          "border-color": isSelected ? selectedNodeStyle.borderColor : defaultNodeStyle.borderColor,
          "shadow-color": isSelected ? selectedNodeStyle.shadowColor : defaultNodeStyle.shadowColor,
          "shadow-opacity": isSelected ? selectedNodeStyle.shadowOpacity : defaultNodeStyle.shadowOpacity
        });
      }, 220);
    }, index * 240);
  });

  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    const nodeData = node.data();
    const assetDetailsPanel = document.querySelector('[aria-label="Asset details panel"]');

    if (selectedNodeId) {
      const prevNode = cy.getElementById(selectedNodeId);
      if (prevNode && !prevNode.empty()) {
        prevNode.style({
          "background-color": defaultNodeStyle.backgroundColor,
          "border-width": defaultNodeStyle.borderWidth,
          "border-color": defaultNodeStyle.borderColor,
          "shadow-color": defaultNodeStyle.shadowColor,
          "shadow-opacity": defaultNodeStyle.shadowOpacity
        });
      }
    }

    selectedNodeId = node.id();
    node.style({
      "background-color": selectedNodeStyle.backgroundColor,
      "border-width": selectedNodeStyle.borderWidth,
      "border-color": selectedNodeStyle.borderColor,
      "shadow-color": selectedNodeStyle.shadowColor,
      "shadow-opacity": selectedNodeStyle.shadowOpacity
    });

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

    const assetName = nodeData.label || nodeData.id || "Unknown";
    const assetId = nodeData.id || "Unknown";
    const assetType = nodeData.type || "Unknown";

    assetDetailsPanel.innerHTML = `
      <h3>Asset Details</h3>
      <p><strong>Name:</strong> ${assetName}</p>
      <p><strong>ID:</strong> ${assetId}</p>
      <p><strong>Type:</strong> ${assetType}</p>
    `;
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

function initGraph() {
  const graphContainer = document.getElementById("cy");

  if (!graphContainer) {
    console.error("Graph container not found");
    return;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initGraph();

  updateStatus(`Frontend ready. API base URL: ${API_BASE_URL}`);

  const sidebarButtons = document.querySelectorAll(".sidebar button");
  const attackPathItem = Array.from(sidebarButtons).find(
    (button) => button.textContent?.trim() === "/attack-path"
  );

  if (attackPathItem) {
    attackPathItem.addEventListener("click", fetchAttackPath);
  }
});
