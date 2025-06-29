import QtQuick 2.15
import QtQuick.Controls 2.15
import QtLocation 5.15
import QtPositioning 5.15

Rectangle {
    id: mapContainer
    width: 800
    height: 600
    color: "#f0f0f0"
    border.color: "#ccc"
    border.width: 1

    signal mapClicked(double latitude, double longitude)

    // OpenStreetMap Plugin
    Plugin {
        id: mapPlugin
        name: "osm"
        PluginParameter {
            name: "osm.useragent"
            value: "TacticalMapClient"
        }
        PluginParameter {
            name: "osm.mapping.host"
            value: "https://tile.openstreetmap.org/"
        }
    }

    // Ana harita
    Map {
        id: map
        anchors.fill: parent
        anchors.margins: 2
        plugin: mapPlugin
        
        // Varsayılan konum - Türkiye merkezi (Ankara)
        center: QtPositioning.coordinate(39.925533, 32.866287)
        zoomLevel: 6
        
        // Dahili kontrolleri gizle
        copyrightsVisible: false
        
        // Gelişmiş Mouse Area - Basit tıklama ve sürükleme
        MouseArea {
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton | Qt.RightButton | Qt.MiddleButton
            
            property bool isDragging: false
            property point lastMousePosition
            property real dragThreshold: 5 // Minimum pixel mesafesi sürükleme için
            property point pressPosition
            
            // Sol tık basılı tutma
            onPressed: function(mouse) {
                if (mouse.button === Qt.LeftButton) {
                    isDragging = false
                    lastMousePosition = Qt.point(mouse.x, mouse.y)
                    pressPosition = Qt.point(mouse.x, mouse.y)
                }
            }
            
            // Mouse hareket - sürükleme
            onPositionChanged: function(mouse) {
                if (mouse.buttons & Qt.LeftButton) {
                    var currentPos = Qt.point(mouse.x, mouse.y)
                    var distanceFromPress = Math.sqrt(
                        Math.pow(currentPos.x - pressPosition.x, 2) + 
                        Math.pow(currentPos.y - pressPosition.y, 2)
                    )
                    
                    // Eğer yeterli mesafe hareket ettiyse sürükleme başlat
                    if (distanceFromPress > dragThreshold) {
                        isDragging = true
                    }
                    
                    if (isDragging) {
                        var deltaX = currentPos.x - lastMousePosition.x
                        var deltaY = currentPos.y - lastMousePosition.y
                        
                        // Haritayı hareket ettir
                        var currentCenter = map.center
                        var newCenter = map.toCoordinate(Qt.point(
                            map.fromCoordinate(currentCenter).x - deltaX,
                            map.fromCoordinate(currentCenter).y - deltaY
                        ))
                        map.center = newCenter
                    }
                    
                    lastMousePosition = currentPos
                }
            }
            
            // Mouse bırakma
            onReleased: function(mouse) {
                if (mouse.button === Qt.LeftButton) {
                    if (!isDragging) {
                        // Sadece tıklama - işaretçi koy
                        var coord = map.toCoordinate(Qt.point(mouse.x, mouse.y))
                        console.log("Tıklanan koordinat:", coord.latitude, coord.longitude)
                        
                        // Mevcut işaretçileri temizle
                        // map.clearMapItems()
                        
                        // Önceki geçici markerları sil
                        for (var i = markers.length - 1; i >= 0; --i) {
                            if (markers[i].isTemporary) {
                                markers[i].destroy();
                                markers.splice(i, 1);
                            }
                        }
                        // Yeni geçici marker ekle
                        var marker = markerComponent.createObject(map, {
                            "coordinate": coord,
                            "isTemporary": true,
                            "description": "",
                            "status": "",
                            "id": "",
                            "timestamp": "",
                            "visible": true
                        })
                        map.addMapItem(marker)
                        markers.push(marker)
                        
                        // Sinyali gönder
                        mapContainer.mapClicked(coord.latitude, coord.longitude)
                    }
                    isDragging = false
                }
            }
            
            // Mouse wheel - zoom
            onWheel: function(wheel) {
                var zoomDelta = wheel.angleDelta.y / 120 // Her wheel step için 1 birim
                var newZoomLevel = map.zoomLevel + (zoomDelta * 0.5)
                map.zoomLevel = Math.max(map.minimumZoomLevel, 
                                       Math.min(map.maximumZoomLevel, newZoomLevel))
            }
        }

        
        // Zoom kontrolleri - Daha büyük + ve - yazıları
        Rectangle {
            id: zoomControls
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.margins: 10
            width: 50
            height: 100
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 5
            opacity: 0.9
            
            Column {
                anchors.centerIn: parent
                spacing: 10
                
                Button {
                    text: "+"
                    width: 40
                    height: 40
                    font.pixelSize: 20
                    font.bold: true
                    onClicked: map.zoomLevel = Math.min(map.zoomLevel + 1, map.maximumZoomLevel)
                }
                
                Button {
                    text: "−"
                    width: 40
                    height: 40
                    font.pixelSize: 24
                    font.bold: true
                    onClicked: map.zoomLevel = Math.max(map.zoomLevel - 1, map.minimumZoomLevel)
                }
            }
        }
        
        // Konum bilgisi
        Rectangle {
            id: coordinateDisplay
            anchors.left: parent.left
            anchors.bottom: parent.bottom
            anchors.margins: 10
            width: 280
            height: 20
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 3
            opacity: 0.9
            
            Text {
                anchors.centerIn: parent
                text: "Merkez: " + map.center.latitude.toFixed(4) + ", " + map.center.longitude.toFixed(4)
                font.pixelSize: 10
                color: "#333"
            }
        }
        
        // Kontrol bilgisi
        Rectangle {
            id: controlInfo
            anchors.right: parent.right
            anchors.bottom: zoomDisplay.top
            anchors.margins: 10
            width: 150
            height: 60
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 3
            opacity: 0.8
            
            Text {
                anchors.centerIn: parent
                text: "Sol Tık: İşaretle\nSol Tık+Sürükle: Hareket\nMouse Wheel: Zoom"
                font.pixelSize: 9
                color: "#333"
                horizontalAlignment: Text.AlignHCenter
            }
        }
        
        // Zoom seviyesi göstergesi
        Rectangle {
            id: zoomDisplay
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.margins: 10
            width: 80
            height: 25
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 3
            opacity: 0.9
            
            Text {
                anchors.centerIn: parent
                text: "Zoom: " + map.zoomLevel.toFixed(1)
                font.pixelSize: 10
                color: "#333"
            }
        }
        
        // Harita türü seçici - Daha geniş dropdown
        Rectangle {
            id: mapTypeSelector
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.margins: 10
            width: 200  // Genişlik artırıldı
            height: 35  // Yükseklik artırıldı
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 3
            opacity: 0.9
            
            ComboBox {
                anchors.fill: parent
                anchors.margins: 2
                model: map.supportedMapTypes
                textRole: "description"
                font.pixelSize: 11
                
                // Dropdown genişliğini ayarla
                popup.width: 220
                
                onCurrentIndexChanged: {
                    if (currentIndex >= 0 && currentIndex < map.supportedMapTypes.length) {
                        map.activeMapType = map.supportedMapTypes[currentIndex]
                    }
                }
            }
        }
    }
    
    // İşaretçi komponenti
    Component {
        id: markerComponent
        MapQuickItem {
            id: marker
            sourceItem: Rectangle {
                width: 16
                height: 16
                radius: 8
                // Renk eşlemesi fonksiyonu
                property string dataType: status
                color: marker.getColorForType(dataType)
                border.width: 3
                border.color: "white"
                Rectangle {
                    anchors.centerIn: parent
                    width: 6
                    height: 6
                    radius: 3
                    color: "white"
                }
                SequentialAnimation on scale {
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 1.2; duration: 800 }
                    NumberAnimation { from: 1.2; to: 1.0; duration: 800 }
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (marker.isTemporary) {
                            // Geçici marker'ı kaldır
                            for (var i = markers.length - 1; i >= 0; --i) {
                                if (markers[i] === marker) {
                                    markers[i].destroy();
                                    markers.splice(i, 1);
                                    break;
                                }
                            }
                        } else {
                            Qt.callLater(function() {
                                marker.showDetails();
                            });
                        }
                    }
                    cursorShape: Qt.PointingHandCursor
                }
            }
            coordinate: QtPositioning.coordinate(0, 0)
            // --- Sadeleştirilmiş property'ler ---
            property string id: ""
            property string status: ""
            property string description: ""
            property string timestamp: ""
            property bool isTemporary: false
            // Renk eşlemesi fonksiyonu
            function getColorForType(type) {
                switch(type) {
                    case "Tehlike": return "#e53935"; // Kırmızı
                    case "Taktik Pozisyon": return "#3949ab"; // Mavi
                    case "Bilgi": return "#43a047"; // Yeşil
                    case "Uyarı": return "#fbc02d"; // Sarı
                    case "Destek": return "#00897b"; // Turkuaz
                    // ... diğer veri tipleri ...
                    default: return "#757575"; // Tanımsız/gri
                }
            }
            function showDetails() {
                var details =
                    "<b>ID:</b> " + id + "<br>" +
                    "<b>Durum:</b> " + status + "<br>" +
                    "<b>Açıklama:</b> " + description + "<br>" +
                    "<b>Zaman:</b> " + timestamp;
                Qt.createQmlObject(
                    'import QtQuick 2.15; import QtQuick.Controls 2.15; Popup { width: 320; height: 120; modal: false; focus: true; contentItem: Text { text: "' + details.replace(/"/g, '\\"') + '"; wrapMode: Text.Wrap; anchors.centerIn: parent; font.pixelSize: 13; textFormat: Text.RichText; } }',
                    map,
                    "dynamicPopup"
                ).open();
            }
        }
    }
    
    // Yükleme göstergesi
    Rectangle {
        id: loadingIndicator
        anchors.centerIn: parent
        width: 200
        height: 50
        color: "white"
        border.color: "#ccc"
        border.width: 1
        radius: 5
        visible: map.supportedMapTypes.length === 0 || map.mapReady === false
        
        Text {
            anchors.centerIn: parent
            text: "Harita yükleniyor..."
            font.pixelSize: 14
        }
        
        // Yükleme çubuğu
        Rectangle {
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.margins: 5
            height: 4
            color: "#e0e0e0"
            radius: 2
            
            Rectangle {
                id: progressBar
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: parent.width * 0.7
                color: "#4CAF50"
                radius: 2
                
                NumberAnimation on width {
                    loops: Animation.Infinite
                    from: 0
                    to: progressBar.parent ? progressBar.parent.width : 100
                    duration: 2000
                }
            }
        }
    }
    
    // Marker yönetim fonksiyonları
    property bool visibleMarkers: true
    property var markers: []

    function setMarkersVisible(visible) {
        visibleMarkers = visible;
        for (var i = 0; i < markers.length; ++i) {
            if (!markers[i].isTemporary) {
                markers[i].visible = visible;
            }
        }
        console.log("[QML] Marker görünürlüğü (sadece rapor markerları):", visible);
    }

    function addMarker(lat, lon, desc, status, id, timestamp, isTemporary) {
        console.log("[QML] [REQ] Marker ekleme isteği: lat=", lat, "lon=", lon, "desc=", desc, "status=", status, "id=", id, "timestamp=", timestamp, "isTemporary=", isTemporary);
        var marker = markerComponent.createObject(map, {
            "coordinate": QtPositioning.coordinate(lat, lon),
            "description": desc,
            "status": status,
            "id": id,
            "timestamp": timestamp,
            "isTemporary": isTemporary === true,
            "visible": isTemporary === true ? true : visibleMarkers
        });
        if (marker) {
            map.addMapItem(marker);
            markers.push(marker);
            console.log("[QML] [RESP] Marker eklendi:", lat, lon, desc, status, id, timestamp, isTemporary);
        }
    }
    function clearMapItems() {
        console.log("[QML] [REQ] Tüm markerları temizle isteği");
        for (var i = 0; i < markers.length; ++i) {
            markers[i].destroy();
        }
        markers = [];
        console.log("[QML] [RESP] Tüm markerlar temizlendi");
    }
}
