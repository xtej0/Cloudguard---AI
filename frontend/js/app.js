const API_BASE_URL = "http://localhost:8000";

console.log("App loaded");

async function fetchAttackPath() {}

function initGraph() {
  const graphContainer = document.getElementById("graph");

  if (!graphContainer || typeof cytoscape === "undefined") {
    console.error("Graph container or Cytoscape is not available.");
    return;
  }

  const cy = cytoscape({
    container: graphContainer,
    elements: [],
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "background-color": "#35d0ba",
          color: "#0b0f14",
          "font-size": 11,
          "text-valign": "center",
          "text-halign": "center"
        }
      },
      {
        selector: "edge",
        style: {
          width: 2,
          "line-color": "#8ca1b8",
          "target-arrow-color": "#8ca1b8",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier"
        }
      }
    ],
    layout: {
      name: "grid"
    }
  });

  window.cloudguardCy = cy;
}

document.addEventListener("DOMContentLoaded", () => {
  initGraph();

  const statusLog = document.getElementById("statusLog");
  if (statusLog) {
    statusLog.textContent = `Frontend ready. API base URL: ${API_BASE_URL}`;
  }
});
