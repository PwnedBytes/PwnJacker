// Main app initialization
document.addEventListener('DOMContentLoaded', function() {
  console.log('PwnJacker Dashboard loaded');
  // Initialize WebSocket if on dashboard
  if (window.location.pathname === '/') {
    initWebSocket();
  }
});