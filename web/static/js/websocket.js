function connectWebSocket() {
  const ws = new WebSocket('ws://' + location.host + '/ws');
  ws.onopen = () => console.log('WebSocket connected');
  ws.onclose = () => setTimeout(connectWebSocket, 3000);
  ws.onerror = (err) => console.error('WebSocket error', err);
  return ws;
}