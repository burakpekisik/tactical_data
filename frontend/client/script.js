// Global variables
let map
let currentMarker = null
let isConnected = false
let selectedCoords = { lat: 39.59107, lng: 33.029794 }
const L = window.L // Declare the L variable

// Initialize the application
function initializeApp() {
  initializeMap()
  setupEventListeners()

  // Simulate initial connection after 1 second
  setTimeout(() => {
    toggleConnection()
  }, 1000)
}

// Initialize the map
function initializeMap() {
  // Create map centered on Turkey
  map = L.map("map").setView([selectedCoords.lat, selectedCoords.lng], 6)

  // Add OpenStreetMap tiles
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap contributors",
    maxZoom: 18,
  }).addTo(map)

  // Add initial marker
  addMarker(selectedCoords.lat, selectedCoords.lng)

  // Set up map click event
  map.on("click", handleMapClick)
}

// Setup event listeners
function setupEventListeners() {
  // Prevent form submission on enter key
  document.addEventListener("keypress", (e) => {
    if (e.key === "Enter" && e.target.tagName !== "BUTTON") {
      e.preventDefault()
    }
  })
}

// Handle map click events
function handleMapClick(e) {
  const lat = e.latlng.lat.toFixed(6)
  const lng = e.latlng.lng.toFixed(6)

  // Update selected coordinates
  selectedCoords = { lat: Number.parseFloat(lat), lng: Number.parseFloat(lng) }

  // Update marker
  addMarker(lat, lng)

  // Update UI elements
  updateCoordinateDisplays(lat, lng)

  // Add to history
  addToHistory(`Nokta seçildi: ${lat}, ${lng}`)
}

// Add or update marker on map
function addMarker(lat, lng) {
  // Remove existing marker
  if (currentMarker) {
    map.removeLayer(currentMarker)
  }

  // Add new marker
  currentMarker = L.marker([lat, lng]).addTo(map)
  currentMarker.bindPopup(`Seçili Nokta<br>Lat: ${lat}<br>Lng: ${lng}`).openPopup()
}

// Update coordinate displays in UI
function updateCoordinateDisplays(lat, lng) {
  document.getElementById("current-coords").textContent = `Koordinat: ${lat}, ${lng}`
  document.getElementById("selected-coords").textContent = `Seçili Nokta: ${lat}, ${lng}`
}

// Toggle server connection
function toggleConnection() {
  const connectBtn = document.getElementById("connect-btn")
  const disconnectBtn = document.getElementById("disconnect-btn")
  const status = document.getElementById("connection-status")
  const address = document.getElementById("server-address").value
  const port = document.getElementById("server-port").value

  if (!isConnected) {
    // Connect to server
    connectToServer(connectBtn, disconnectBtn, status, address, port)
  } else {
    // Disconnect from server
    disconnectFromServer(connectBtn, disconnectBtn, status, address, port)
  }
}

// Connect to server
function connectToServer(connectBtn, disconnectBtn, status, address, port) {
  // Validate inputs
  if (!address || !port) {
    alert("Lütfen geçerli bir adres ve port girin!")
    return
  }

  isConnected = true
  connectBtn.disabled = true
  disconnectBtn.disabled = false
  status.textContent = "Bağlantı Durumu: Bağlı"
  status.className = "status-connected"
  addToHistory(`Sunucuya bağlanıldı: ${address}:${port}`)
}

// Disconnect from server
function disconnectFromServer(connectBtn, disconnectBtn, status, address, port) {
  isConnected = false
  connectBtn.disabled = false
  disconnectBtn.disabled = true
  status.textContent = "Bağlantı Durumu: Bağlı Değil"
  status.className = "status-disconnected"
  addToHistory(`Sunucu bağlantısı kesildi: ${address}:${port}`)
}

// Send data to server
function sendData() {
  if (!isConnected) {
    alert("Önce sunucuya bağlanmalısınız!")
    return
  }

  const dataType = document.getElementById("data-type").value
  const message = document.getElementById("message").value

  // Validate message
  if (!message.trim()) {
    alert("Lütfen bir mesaj girin!")
    return
  }

  // Log data sending
  addToHistory(`Veri gönderildi: ${dataType} - ${selectedCoords.lat}, ${selectedCoords.lng}`)
  addToHistory(`Mesaj: "${message}"`)

  // Simulate data sending with delay
  setTimeout(() => {
    addToHistory("Veri başarıyla gönderildi")
  }, 500)

  // Show success feedback
  showTemporaryFeedback("Veri gönderiliyor...", "success")
}

// Set port value
function setPort(port) {
  document.getElementById("server-port").value = port
}

// Add entry to history log
function addToHistory(message) {
  const historyLog = document.getElementById("history-log")
  const timestamp = getCurrentTimestamp()

  const logEntry = document.createElement("div")
  logEntry.className = "log-entry"
  logEntry.textContent = `${message} - ${timestamp}`

  historyLog.appendChild(logEntry)
  historyLog.scrollTop = historyLog.scrollHeight
}

// Get current timestamp in Turkish format
function getCurrentTimestamp() {
  const now = new Date()
  const options = {
    weekday: "short",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    year: "numeric",
  }

  return now.toLocaleString("tr-TR", options)
}

// Show temporary feedback message
function showTemporaryFeedback(message, type = "info") {
  const feedback = document.createElement("div")
  feedback.className = `alert alert-${type} alert-dismissible fade show position-fixed`
  feedback.style.cssText = "top: 20px; right: 20px; z-index: 9999; min-width: 300px;"
  feedback.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `

  document.body.appendChild(feedback)

  // Auto remove after 3 seconds
  setTimeout(() => {
    if (feedback.parentNode) {
      feedback.parentNode.removeChild(feedback)
    }
  }, 3000)
}

// Utility function to format coordinates
function formatCoordinate(coord, precision = 6) {
  return Number.parseFloat(coord).toFixed(precision)
}

// Clear history log
function clearHistory() {
  const historyLog = document.getElementById("history-log")
  historyLog.innerHTML = ""
  addToHistory("Geçmiş temizlendi")
}

// Export coordinates to clipboard
function exportCoordinates() {
  const coords = `${selectedCoords.lat}, ${selectedCoords.lng}`
  navigator.clipboard
    .writeText(coords)
    .then(() => {
      showTemporaryFeedback("Koordinatlar panoya kopyalandı!", "success")
    })
    .catch(() => {
      showTemporaryFeedback("Kopyalama başarısız!", "danger")
    })
}

// Initialize app when DOM is loaded
document.addEventListener("DOMContentLoaded", initializeApp)

// Handle window resize
window.addEventListener("resize", () => {
  if (map) {
    setTimeout(() => {
      map.invalidateSize()
    }, 100)
  }
})
