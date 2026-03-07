function initWebSocket() {
    const ws = new WebSocket('ws://' + window.location.host + '/ws');
    ws.onmessage = function(event) {
        const finding = JSON.parse(event.data);
        addFindingToTable(finding);
        updateStats(finding);
        updateCharts(finding);
    };
}

function addFindingToTable(finding) { /* ... as in dashboard.html ... */ }
function updateStats(finding) { /* ... */ }
function updateCharts(finding) { /* ... */ }