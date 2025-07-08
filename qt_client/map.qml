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
    signal markerClicked(int id, double latitude, double longitude, string markerType, string description, string status, string timestamp)
    signal currentLocationMarkerClicked(double latitude, double longitude)
    function emitMarkerClicked(markerId, lat, lon, markerType, description, status, timestamp) {
        mapContainer.markerClicked(markerId, lat, lon, markerType, description, status, timestamp);
    }
    
    // Mevcut konum için değişkenler
    property bool hasCurrentLocation: false
    property double currentLat: 0.0
    property double currentLon: 0.0

    // QUERY_MY_REPLIES'den dönen id listesi
    property var replyIdList: []
    function setReplyIdList(idList) {
        replyIdList = idList;
        console.log("[QML] replyIdList güncellendi, boyut:", replyIdList.length, "liste:", JSON.stringify(replyIdList));
        
        // Mevcut marker'ları kontrol et
        for (var i = 0; i < markers.length; ++i) {
            var marker = markers[i];
            if (!marker.isTemporary && marker.id !== undefined) {
                var hasReply = replyIdList.indexOf(marker.id) !== -1;
                // console.log("[QML] Marker ID:", marker.id, "hasReply:", hasReply);
            }
        }
    }

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
        
        // Varsayılan konum - Türkiye merkezi
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
                    console.log("[QML] Mouse released - isDragging:", isDragging, "allowAddMarker:", allowAddMarker)
                    if (!isDragging && allowAddMarker === true) {
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
                            "id": -1,
                            "timestamp": "",
                            "visible": true
                        })
                        map.addMapItem(marker)
                        markers.push(marker)
                        mapContainer.mapClicked(coord.latitude, coord.longitude)
                    } else if (!isDragging && allowAddMarker === false) {
                        console.log("[QML] Marker ekleme engellendi - Dönüt yap modunda")
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

        
        // Zoom kontrolleri - Server ile aynı tasarım
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
                
                Rectangle {
                    width: 40
                    height: 40
                    color: "#f0f0f0"
                    border.color: "#aaa"
                    border.width: 1
                    radius: 4
                    
                    Text {
                        anchors.centerIn: parent
                        text: "+"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#333"
                    }
                    
                    MouseArea {
                        anchors.fill: parent
                        onClicked: map.zoomLevel = Math.min(map.zoomLevel + 1, map.maximumZoomLevel)
                        
                        // Hover efekti
                        hoverEnabled: true
                        onEntered: parent.color = "#e0e0e0"
                        onExited: parent.color = "#f0f0f0"
                        onPressed: parent.color = "#d0d0d0"
                        onReleased: parent.color = "#e0e0e0"
                    }
                }
                
                Rectangle {
                    width: 40
                    height: 40
                    color: "#f0f0f0"
                    border.color: "#aaa"
                    border.width: 1
                    radius: 4
                    
                    Text {
                        anchors.centerIn: parent
                        text: "−"
                        font.pixelSize: 26
                        font.bold: true
                        color: "#333"
                    }
                    
                    MouseArea {
                        anchors.fill: parent
                        onClicked: map.zoomLevel = Math.max(map.zoomLevel - 1, map.minimumZoomLevel)
                        
                        // Hover efekti
                        hoverEnabled: true
                        onEntered: parent.color = "#e0e0e0"
                        onExited: parent.color = "#f0f0f0"
                        onPressed: parent.color = "#d0d0d0"
                        onReleased: parent.color = "#e0e0e0"
                    }
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
    // Report marker komponenti
    Component {
        id: markerComponent
        MapQuickItem {
            id: marker
            sourceItem: Rectangle {
                width: 16
                height: 16
                radius: 8
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
                            for (var i = reportMarkers.length - 1; i >= 0; --i) {
                                if (reportMarkers[i] === marker) {
                                    reportMarkers[i].destroy();
                                    reportMarkers.splice(i, 1);
                                    break;
                                }
                            }
                        } else if (marker.id !== -1) {
                            Qt.callLater(function() {
                                marker.showDetails();
                                mapContainer.emitMarkerClicked(marker.id, marker.coordinate.latitude, marker.coordinate.longitude, "report", marker.description, marker.status, marker.timestamp);
                            });
                        }
                    }
                    cursorShape: Qt.PointingHandCursor
                }
            }
            coordinate: QtPositioning.coordinate(0, 0)
            property int id: -1
            property string status: ""
            property string description: ""
            property string timestamp: ""
            property bool isTemporary: false
            function getColorForType(type) {
                switch(type) {
                    case "Tehlike": return "#e53935"; // Kırmızı
                    case "Taktik Pozisyon": return "#3949ab"; // Mavi
                    case "Düşman Teması": return "#fbc02d"; // Sarı
                    case "Dost Birim": return "#43a047"; // Yeşil
                    case "Hedef": return "#00897b"; // Turkuaz
                    default: return "#757575";
                }
            }
            function formatTimestamp(timestamp) {
                var date = new Date(parseInt(timestamp) * 1000);
                var day = ("0" + date.getDate()).slice(-2);
                var month = ("0" + (date.getMonth() + 1)).slice(-2);
                var year = date.getFullYear();
                var hours = ("0" + date.getHours()).slice(-2);
                var minutes = ("0" + date.getMinutes()).slice(-2);
                var seconds = ("0" + date.getSeconds()).slice(-2);
                return day + "." + month + "." + year + " " + hours + ":" + minutes + ":" + seconds;
            }
            function showDetails() {
                var formattedTime = timestamp ? formatTimestamp(timestamp) : "Bilinmiyor";
                var details = "";
                if (typeof status === "string" && status.length > 0) {
                    // Report marker
                    details =
                        "<b>ID:</b> " + id + "<br>" +
                        "<b>Durum:</b> " + status + "<br>" +
                        "<b>Açıklama:</b> " + description + "<br>" +
                        "<b>Zaman:</b> " + formattedTime;
                } else {
                    // User marker (status boş veya yok)
                    details =
                        "<b>Kullanıcı ID:</b> " + id + "<br>" +
                        "<b>Enlem:</b> " + coordinate.latitude.toFixed(6) + "<br>" +
                        "<b>Boylam:</b> " + coordinate.longitude.toFixed(6) + "<br>" +
                        "<b>Zaman:</b> " + formattedTime;
                }
                Qt.createQmlObject(
                    'import QtQuick 2.15; import QtQuick.Controls 2.15; Popup { width: 320; height: 120; modal: false; focus: true; contentItem: Text { text: "' + details.replace(/"/g, '\\"') + '"; wrapMode: Text.Wrap; anchors.centerIn: parent; font.pixelSize: 13; textFormat: Text.RichText; } }',
                    map,
                    "dynamicPopup"
                ).open();
            }
        }
    }

    // User marker komponenti (daha büyük, farklı renkli, border'ı siyah)
    Component {
        id: userMarkerComponent
        MapQuickItem {
            id: userMarker
            sourceItem: Rectangle {
                width: 22
                height: 22
                radius: 11
                color: "#ff9800" // Turuncu
                border.width: 4
                border.color: "#222" // Siyah
                Rectangle {
                    anchors.centerIn: parent
                    width: 8
                    height: 8
                    radius: 4
                    color: "white"
                }
                SequentialAnimation on scale {
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 1.18; duration: 900 }
                    NumberAnimation { from: 1.18; to: 1.0; duration: 900 }
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (userMarker.id !== -1) {
                            Qt.callLater(function() {
                                userMarker.showDetails();
                                mapContainer.emitMarkerClicked(userMarker.id, userMarker.coordinate.latitude, userMarker.coordinate.longitude, "user", userMarker.description, userMarker.status, userMarker.timestamp);
                            });
                        }
                    }
                    cursorShape: Qt.PointingHandCursor
                }
            }
            coordinate: QtPositioning.coordinate(0, 0)
            property int id: -1
            property string status: ""
            property string description: ""
            property string timestamp: ""
            property bool isTemporary: false
            function formatTimestamp(timestamp) {
                var date = new Date(parseInt(timestamp) * 1000);
                var day = ("0" + date.getDate()).slice(-2);
                var month = ("0" + (date.getMonth() + 1)).slice(-2);
                var year = date.getFullYear();
                var hours = ("0" + date.getHours()).slice(-2);
                var minutes = ("0" + date.getMinutes()).slice(-2);
                var seconds = ("0" + date.getSeconds()).slice(-2);
                return day + "." + month + "." + year + " " + hours + ":" + minutes + ":" + seconds;
            }
            function showDetails() {
                var formattedTime = timestamp ? formatTimestamp(timestamp) : "Bilinmiyor";
                var details = "";
                if (typeof status === "string" && status.length > 0) {
                    // Report marker
                    details =
                        "<b>ID:</b> " + id + "<br>" +
                        "<b>Durum:</b> " + status + "<br>" +
                        "<b>Açıklama:</b> " + description + "<br>" +
                        "<b>Zaman:</b> " + formattedTime;
                } else {
                    // User marker (status boş veya yok)
                    details =
                        "<b>Kullanıcı ID:</b> " + id + "<br>" +
                        "<b>Enlem:</b> " + coordinate.latitude.toFixed(6) + "<br>" +
                        "<b>Boylam:</b> " + coordinate.longitude.toFixed(6) + "<br>" +
                        "<b>Zaman:</b> " + formattedTime;
                }
                Qt.createQmlObject(
                    'import QtQuick 2.15; import QtQuick.Controls 2.15; Popup { width: 320; height: 120; modal: false; focus: true; contentItem: Text { text: "' + details.replace(/"/g, '\\"') + '"; wrapMode: Text.Wrap; anchors.centerIn: parent; font.pixelSize: 13; textFormat: Text.RichText; } }',
                    map,
                    "dynamicUserPopup"
                ).open();
            }
        }
    }
    
    // Mevcut konum işaretçisi komponenti
    Component {
        id: currentLocationComponent
        MapQuickItem {
            id: currentLocationMarker
            sourceItem: Rectangle {
                width: 24
                height: 24
                radius: 12
                color: "#2196F3"
                border.color: "white"
                border.width: 4
                
                // İç nokta
                Rectangle {
                    anchors.centerIn: parent
                    width: 8
                    height: 8
                    radius: 4
                    color: "white"
                }
                
                // Nabız efekti
                SequentialAnimation on scale {
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 1.3; duration: 1000 }
                    NumberAnimation { from: 1.3; to: 1.0; duration: 1000 }
                }
                
                // Dış halka efekti
                Rectangle {
                    anchors.centerIn: parent
                    width: 50
                    height: 50
                    radius: 25
                    color: "transparent"
                    border.color: "#2196F3"
                    border.width: 2
                    opacity: 0.6
                    
                    SequentialAnimation on scale {
                        loops: Animation.Infinite
                        NumberAnimation { from: 0.5; to: 2.0; duration: 2000 }
                    }
                    SequentialAnimation on opacity {
                        loops: Animation.Infinite
                        NumberAnimation { from: 0.8; to: 0.0; duration: 2000 }
                    }
                }
                
                // Tooltip görevi görecek MouseArea
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        console.log("[QML] Current location marker clicked at:", coordinate.latitude, coordinate.longitude);
                        // Signal'i emit et
                        mapContainer.currentLocationMarkerClicked(coordinate.latitude, coordinate.longitude);
                        
                        // Tooltip'i de göster
                        Qt.createQmlObject(
                            'import QtQuick 2.15; import QtQuick.Controls 2.15; Popup { width: 280; height: 80; modal: false; focus: true; contentItem: Text { text: "<b>📍 Mevcut Konumum Seçildi</b><br>Veri gönderimi için seçildi: ' + coordinate.latitude.toFixed(6) + ', ' + coordinate.longitude.toFixed(6) + '"; wrapMode: Text.Wrap; anchors.centerIn: parent; font.pixelSize: 13; textFormat: Text.RichText; horizontalAlignment: Text.AlignHCenter; } }',
                            map,
                            "currentLocationPopup"
                        ).open();
                    }
                }
            }
            coordinate: QtPositioning.coordinate(0, 0)
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
    // Report ve user marker'larını ayrı ayrı tut
    property var reportMarkers: []
    property var userMarkers: []
    property var markers: [] // Geriye dönük uyumluluk için, sadece reportMarkers ile aynı olacak
    property var currentLocationMarker: null
    // allowAddMarker context property olarak C++'tan geliyor
    
    function setMarkersVisible(visible) {
        visibleMarkers = visible;
        for (var i = 0; i < markers.length; ++i) {
            if (!markers[i].isTemporary) {
                markers[i].visible = visible;
            }
        }
        console.log("[QML] Marker görünürlüğü (sadece rapor markerları):", visible);
    }

    // markerType: "report" veya "user" (zorunlu!)
    function addMarker(lat, lon, desc, status, id, timestamp, isTemporary, markerType) {
        // Varsayılan markerType: report (eski çağrılar için)
        if (markerType === undefined) markerType = "report";
        var markerObj;
        if (markerType === "user") {
            markerObj = userMarkerComponent.createObject(map, {
                "coordinate": QtPositioning.coordinate(lat, lon),
                "description": desc,
                "status": status,
                "id": id,
                "timestamp": timestamp,
                "isTemporary": isTemporary === true,
                "visible": true
            });
            if (markerObj) {
                map.addMapItem(markerObj);
                userMarkers.push(markerObj);
            }
        } else {
            markerObj = markerComponent.createObject(map, {
                "coordinate": QtPositioning.coordinate(lat, lon),
                "description": desc,
                "status": status,
                "id": id,
                "timestamp": timestamp,
                "isTemporary": isTemporary === true,
                "visible": isTemporary === true ? true : visibleMarkers
            });
            if (markerObj) {
                map.addMapItem(markerObj);
                reportMarkers.push(markerObj);
                markers.push(markerObj); // markers sadece report marker'ları için
            }
        }
    }
    // markerType: "report", "user", veya undefined (hepsi)
    function clearMapItems(markerType) {
        if (markerType === "user") {
            for (var i = 0; i < userMarkers.length; ++i) {
                userMarkers[i].destroy();
            }
            userMarkers = [];
            console.log("[QML] [RESP] User markerlar temizlendi");
        } else if (markerType === "report") {
            for (var i = 0; i < reportMarkers.length; ++i) {
                reportMarkers[i].destroy();
            }
            reportMarkers = [];
            markers = [];
            console.log("[QML] [RESP] Report markerlar temizlendi");
        } else {
            // Hepsi
            for (var i = 0; i < userMarkers.length; ++i) {
                userMarkers[i].destroy();
            }
            userMarkers = [];
            for (var i = 0; i < reportMarkers.length; ++i) {
                reportMarkers[i].destroy();
            }
            reportMarkers = [];
            markers = [];
            // Mevcut konum marker'ını da temizle
            if (currentLocationMarker) {
                map.removeMapItem(currentLocationMarker);
                currentLocationMarker.destroy();
                currentLocationMarker = null;
                hasCurrentLocation = false;
            }
            console.log("[QML] [RESP] Tüm markerlar temizlendi");
        }
    }
    
    function setCurrentLocation(lat, lon) {
        console.log("[QML] [REQ] Mevcut konum ayarlanıyor:", lat, lon);
        
        // Önceki mevcut konum marker'ını temizle
        if (currentLocationMarker) {
            map.removeMapItem(currentLocationMarker);
            currentLocationMarker.destroy();
        }
        
        // Mevcut konum marker'ını oluştur - diğer markerlardan farklı görünüm
        currentLocationMarker = currentLocationComponent.createObject(map, {
            coordinate: QtPositioning.coordinate(lat, lon)
        });
        
        if (currentLocationMarker) {
            map.addMapItem(currentLocationMarker);
            hasCurrentLocation = true;
            currentLat = lat;
            currentLon = lon;
            
            // Zoom ve center işlemini kaldırdık - sadece marker ekliyoruz
            console.log("[QML] [RESP] Mevcut konum marker'ı eklendi:", lat, lon);
        } else {
            console.log("[QML] [ERROR] Mevcut konum marker'ı oluşturulamadı");
        }
    }
    
    // Marker filtreleme fonksiyonları
    function applyFilters(dataTypeFilter, replyStatusFilter, timeFilter) {
        console.log("[QML] Filtreler uygulanıyor:", dataTypeFilter, replyStatusFilter, timeFilter);
        
        var visibleCount = 0;
        for (var i = 0; i < markers.length; ++i) {
            var marker = markers[i];
            if (!marker.isTemporary) {
                var markerDataType = getMarkerDataType(marker.description);
                var visible = isMarkerVisibleByFilter(marker, dataTypeFilter, replyStatusFilter, timeFilter);
                marker.visible = visible;
                
                console.log("[QML] Marker", i, "- ID:", marker.id, "Type:", markerDataType, "Description:", marker.description, "Visible:", visible);
                if (visible) visibleCount++;
            }
        }
        console.log("[QML] Marker filtreleri uygulandı. Görünür marker sayısı:", visibleCount);
    }
    
    function clearFilters() {
        console.log("[QML] Tüm filtreler temizleniyor");
        
        for (var i = 0; i < markers.length; ++i) {
            var marker = markers[i];
            if (!marker.isTemporary) {
                marker.visible = visibleMarkers;
            }
        }
        console.log("[QML] Tüm filtreler temizlendi");
    }
    
    function isMarkerVisibleByFilter(marker, dataTypeFilter, replyStatusFilter, timeFilter) {
        // Veri tipi filtresi
        if (dataTypeFilter !== "Tümü") {
            var markerDataType = getMarkerDataType(marker.status);
            console.log("[QML] Filtreleme - Marker Type:", markerDataType, "Filter:", dataTypeFilter, "Status:", marker.status);
            if (markerDataType !== dataTypeFilter) {
                console.log("[QML] Marker gizlendi - veri tipi uyuşmuyor");
                return false;
            }
        }
        
        // Reply durumu filtresi
        if (replyStatusFilter !== "Tümü") {
            var hasReply = false;
            if (replyIdList && replyIdList.length > 0 && marker.id !== undefined) {
                hasReply = replyIdList.indexOf(marker.id) !== -1;
            } else {
                hasReply = marker.status.indexOf("Reply") !== -1 || marker.status.indexOf("REPLYED") !== -1;
            }
            console.log("[QML] Filtreleme - Reply Status:", marker.status, "Has Reply:", hasReply, "Filter:", replyStatusFilter, "ID:", marker.id, "replyIdList:", replyIdList);
            if (replyStatusFilter === "Reply Var" && !hasReply) {
                return false;
            }
            if (replyStatusFilter === "Reply Yok" && hasReply) {
                return false;
            }
        }
        
        // Zaman filtresi
        if (timeFilter !== "Tümü") {
            // Unix timestamp kontrol ve çevirme
            var timestamp = parseInt(marker.timestamp);
            if (!timestamp || timestamp <= 0) {
                console.log("[QML] Geçersiz timestamp:", marker.timestamp);
                return true; // Geçersiz timestamp'li marker'ları göster
            }
            
            var timestampMs = timestamp * 1000;
            var markerTime = new Date(timestampMs);
            var currentTime = new Date();
            var timeDiff = currentTime.getTime() - markerTime.getTime();
            var hours = timeDiff / (1000 * 60 * 60);
            
            console.log("[QML] Filtreleme - Timestamp:", timestamp, "Marker Time:", markerTime, "Hours ago:", hours, "Filter:", timeFilter);
            
            var maxHours = 0;
            if (timeFilter === "Son 1 Saat") {
                maxHours = 1;
            } else if (timeFilter === "Son 24 Saat") {
                maxHours = 24;
            } else if (timeFilter === "Son 7 Gün") {
                maxHours = 24 * 7;
            } else if (timeFilter === "Son 30 Gün") {
                maxHours = 24 * 30;
            }
            
            if (maxHours > 0 && hours > maxHours) {
                return false;
            }
        }
        
        return true;
    }
    
    function getMarkerDataType(status) {
        // Status'tan veri tipini çıkar
        if (status.indexOf("Tactical Position") !== -1) return "Tactical Position";
        if (status.indexOf("Enemy Contact") !== -1) return "Enemy Contact";
        if (status.indexOf("Friendly Unit") !== -1) return "Friendly Unit";
        if (status.indexOf("Objective") !== -1) return "Objective";
        if (status.indexOf("Hazard") !== -1) return "Hazard";
        
        // Debug için status değerini yazdır
        console.log("[QML DEBUG] Status değeri:", status);
        return "Unknown"; // Bilinmeyen tipler için
    }

    // Belirtilen konuma zoom yapar ve haritayı merkeze alır
    function centerOnLocation(lat, lon) {
        console.log("[QML] centerOnLocation çağrıldı:", lat, lon);
        
        if (map) {
            var coordinate = QtPositioning.coordinate(lat, lon);
            map.center = coordinate;
            map.zoomLevel = Math.max(map.zoomLevel, 15); // En az zoom level 15
            console.log("[QML] Harita konumu güncellendi:", coordinate, "zoom:", map.zoomLevel);
        } else {
            console.log("[QML] Hata: map objesi null!");
        }
    }
    
    // Menü açma butonu (sağ üstte)
    Button {
        id: openRoomMenuButton
        text: "Odalar"
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.topMargin: 12
        anchors.rightMargin: 12
        z: 100
        onClicked: {
            if (!roomMenu) {
                console.log("[QML] RoomMenu component bulunamadı!");
                return;
            }
            mainWindow.fetchChatRoomList();
            roomMenu.open();
        }
    }

    // RoomMenu popup'ı (import edildiği varsayılır)
    RoomMenu {
        id: roomMenu
        anchors.centerIn: parent
        roomList: mainWindow.roomList
        userPrivilege: 0 // Gerekirse C++'tan veya üst QML'den set edilebilir
        onRoomJoined: {
            // Odaya katılınca yapılacaklar
            console.log("Odaya katılındı, ID:", roomId);
        }
    }
}
