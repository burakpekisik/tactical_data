import QtQuick 2.15
import QtQuick.Controls 2.15
import QtLocation 5.15
import QtPositioning 5.15

Rectangle {
    id: serverMapContainer
    width: 800
    height: 600
    color: "#f0f0f0"
    border.color: "#ccc"
    border.width: 1

    property var clientMarkers: []

    // QML'den C++'a erişim için fonksiyonlar
    function addServerMarker(latitude, longitude, dataType, message) {
        console.log("Sunucuya marker ekleniyor:", latitude, longitude, dataType, message)
        
        // Mevcut marker'ları temizle (sadece client marker'ları)
        map.clearMapItems()
        
        // Yeni marker ekle
        var marker = serverMarkerComponent.createObject(map, {
            "coordinate": QtPositioning.coordinate(latitude, longitude),
            "markerType": dataType,
            "markerMessage": message
        })
        map.addMapItem(marker)
        
        // Haritayı yeni konuma odakla
        map.center = QtPositioning.coordinate(latitude, longitude)
        map.zoomLevel = Math.max(map.zoomLevel, 10)
    }
    
    function clearAllMarkers() {
        map.clearMapItems()
        clientMarkers = []
    }

    // OpenStreetMap Plugin
    Plugin {
        id: serverMapPlugin
        name: "osm"
        PluginParameter {
            name: "osm.useragent"
            value: "TacticalMapServer"
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
        plugin: serverMapPlugin
        
        // Varsayılan konum - Türkiye merkezi (Ankara)
        center: QtPositioning.coordinate(39.925533, 32.866287)
        zoomLevel: 6
        
        // Dahili kontrolleri gizle
        copyrightsVisible: false
        
        // Mouse Area - Sadece görüntüleme, tıklama yok
        MouseArea {
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton | Qt.RightButton | Qt.MiddleButton
            
            property bool isDragging: false
            property point lastMousePosition
            property real dragThreshold: 5
            property point pressPosition
            
            onPressed: function(mouse) {
                if (mouse.button === Qt.LeftButton) {
                    isDragging = false
                    lastMousePosition = Qt.point(mouse.x, mouse.y)
                    pressPosition = Qt.point(mouse.x, mouse.y)
                }
            }
            
            onPositionChanged: function(mouse) {
                if (mouse.buttons & Qt.LeftButton) {
                    var currentPos = Qt.point(mouse.x, mouse.y)
                    var distanceFromPress = Math.sqrt(
                        Math.pow(currentPos.x - pressPosition.x, 2) + 
                        Math.pow(currentPos.y - pressPosition.y, 2)
                    )
                    
                    if (distanceFromPress > dragThreshold) {
                        isDragging = true
                    }
                    
                    if (isDragging) {
                        var deltaX = currentPos.x - lastMousePosition.x
                        var deltaY = currentPos.y - lastMousePosition.y
                        
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
            
            onReleased: function(mouse) {
                if (mouse.button === Qt.LeftButton) {
                    isDragging = false
                }
            }
            
            // Mouse wheel - zoom
            onWheel: function(wheel) {
                var zoomDelta = wheel.angleDelta.y / 120
                var newZoomLevel = map.zoomLevel + (zoomDelta * 0.5)
                map.zoomLevel = Math.max(map.minimumZoomLevel, 
                                       Math.min(map.maximumZoomLevel, newZoomLevel))
            }
        }
        
        // Zoom kontrolleri - Client ile aynı tasarım
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
                    }
                }
            }
        }
        
        // Sunucu bilgisi
        Rectangle {
            id: serverInfo
            anchors.left: parent.left
            anchors.bottom: parent.bottom
            anchors.margins: 10
            width: 300
            height: 20
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 3
            opacity: 0.9
            
            Text {
                anchors.centerIn: parent
                text: "Sunucu Görünümü - Merkez: " + map.center.latitude.toFixed(4) + ", " + map.center.longitude.toFixed(4)
                font.pixelSize: 10
                color: "#333"
            }
        }
        
        // Sunucu kontrol bilgisi
        Rectangle {
            id: serverControlInfo
            anchors.right: parent.right
            anchors.bottom: zoomDisplay.top
            anchors.margins: 10
            width: 180
            height: 60
            color: "white"
            border.color: "#ccc"
            border.width: 1
            radius: 3
            opacity: 0.8
            
            Text {
                anchors.centerIn: parent
                text: "İstemci Verileri\nOtomatik Görüntülenir\nSürükle: Hareket, Wheel: Zoom"
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
        
        // Harita türü seçici - Client ile aynı tasarım
        Rectangle {
            id: mapTypeSelector
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.margins: 10
            width: 200
            height: 35
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
                
                popup.width: 220
                
                onCurrentIndexChanged: {
                    if (currentIndex >= 0 && currentIndex < map.supportedMapTypes.length) {
                        map.activeMapType = map.supportedMapTypes[currentIndex]
                    }
                }
            }
        }
    }
    
    // Sunucu marker komponenti - İstemcilerden gelen verileri gösterir
    Component {
        id: serverMarkerComponent
        MapQuickItem {
            id: serverMarker
            
            property string markerType: "Unknown"
            property string markerMessage: ""
            
            sourceItem: Rectangle {
                width: 20
                height: 20
                radius: 10
                
                // Veri tipine göre renk
                color: {
                    switch(markerType) {
                        case "Tactical Position": return "#2196F3"  // Mavi
                        case "Enemy Contact": return "#F44336"      // Kırmızı
                        case "Friendly Unit": return "#4CAF50"      // Yeşil
                        case "Objective": return "#FF9800"         // Turuncu
                        case "Hazard": return "#9C27B0"            // Mor
                        default: return "#607D8B"                  // Gri
                    }
                }
                
                border.width: 3
                border.color: "white"
                
                // İçerdeki nokta
                Rectangle {
                    anchors.centerIn: parent
                    width: 8
                    height: 8
                    radius: 4
                    color: "white"
                }
                
                // Tooltip
                Rectangle {
                    id: tooltip
                    anchors.bottom: parent.top
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.bottomMargin: 5
                    width: tooltipText.width + 10
                    height: tooltipText.height + 6
                    color: "black"
                    opacity: 0.8
                    radius: 3
                    visible: false
                    
                    Text {
                        id: tooltipText
                        anchors.centerIn: parent
                        text: markerType + "\n" + markerMessage
                        color: "white"
                        font.pixelSize: 10
                        horizontalAlignment: Text.AlignHCenter
                    }
                }
                
                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    onEntered: tooltip.visible = true
                    onExited: tooltip.visible = false
                }
                
                // Pulse animasyonu - Yeni veri geldiğinde
                SequentialAnimation on scale {
                    loops: 3
                    NumberAnimation { from: 1.0; to: 1.4; duration: 300 }
                    NumberAnimation { from: 1.4; to: 1.0; duration: 300 }
                }
            }
            coordinate: QtPositioning.coordinate(0, 0)
            anchorPoint.x: sourceItem.width / 2
            anchorPoint.y: sourceItem.height / 2
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
            text: "Sunucu haritası yükleniyor..."
            font.pixelSize: 14
        }
        
        Rectangle {
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.margins: 5
            height: 4
            color: "#e0e0e0"
            radius: 2
            
            Rectangle {
                id: serverProgressBar
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: parent.width * 0.7
                color: "#2196F3"
                radius: 2
                
                NumberAnimation on width {
                    loops: Animation.Infinite
                    from: 0
                    to: serverProgressBar.parent ? serverProgressBar.parent.width : 100
                    duration: 2000
                }
            }
        }
    }
}
