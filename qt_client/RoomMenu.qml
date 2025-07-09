import QtQuick 2.15
import QtQuick.Controls 2.15

Popup {
    id: roomMenu
    width: 900
    height: 500
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    property var roomList: [] // Dışarıdan set edilecek [{name, privilege, current, max, id}]

    property int userPrivilege: 0 // Dışarıdan set edilecek

    // sortBy fonksiyonunu dış QtObject ile erişilebilir yap
    QtObject {
        id: sorter
        function sortBy(column) {
            if (roomMenu.sortColumn === column) {
                roomMenu.sortAsc = !roomMenu.sortAsc;
            } else {
                roomMenu.sortColumn = column;
                roomMenu.sortAsc = true;
            }
            roomMenu.roomList = roomMenu.roomList.slice().sort(function(a, b) {
                if (a[column] < b[column]) return roomMenu.sortAsc ? -1 : 1;
                if (a[column] > b[column]) return roomMenu.sortAsc ? 1 : -1;
                return 0;
            });
        }
    }

    property string sortColumn: "id"
    property bool sortAsc: true


    // CreateRoomPopup import and instance
    CreateRoomPopup {
        id: createRoomPopup
        visible: false
        onCreateRoom: function(name, accessType, userIds) {
        if (typeof mainWindow !== 'undefined' && mainWindow.createChatRoom) {
            mainWindow.createChatRoom(name, accessType, 50, userIds);
        }
        roomMenu.roomCreated(name, accessType, userIds);
    }
    }

    Rectangle {
        anchors.fill: parent
        color: "#f8f8f8"
        border.color: "#cccccc"
        radius: 8

        Column {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 8

            Row {
                width: parent.width
                spacing: 12
                Text {
                    text: "Oda Listesi"
                    font.bold: true
                    font.pointSize: 18
                    color: "#222"
                    horizontalAlignment: Text.AlignHCenter
                    anchors.verticalCenter: parent.verticalCenter
                }
                Item { width: 1; height: 1 } // Spacer
                Button {
                    text: "Oda Oluştur"
                    onClicked: createRoomPopup.visible = true
                    font.bold: true
                    font.pointSize: 14
                    background: Rectangle {
                        color: "#4CAF50"
                        radius: 8
                        border.color: "#388E3C"
                        border.width: 1
                    }
                    contentItem: Text {
                        text: parent.text
                        color: "white"
                        font.bold: true
                        font.pointSize: 14
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        anchors.centerIn: parent
                    }
                    hoverEnabled: true
                    opacity: enabled ? 1.0 : 0.5
                }
            }

            Rectangle {
                width: parent.width
                height: parent.height - 60
                color: "#fff"
                border.color: "#ccc"
                radius: 6

                // Sütun başlıkları (otomatik genişlik, sıralama)
                Row {
                    spacing: 0
                    height: 36
                    width: parent.width
                    Rectangle { width: parent.width * 0.15; height: 36; color: "transparent"
                        Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#bbb" }
                        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#bbb" }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: sorter.sortBy("id")
                            cursorShape: Qt.PointingHandCursor
                        }
                        Text { text: "Oda ID"; anchors.centerIn: parent; font.bold: true; color: "#444" }
                    }
                    Rectangle { width: parent.width * 0.32; height: 36; color: "transparent"
                        Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#bbb" }
                        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#bbb" }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: sorter.sortBy("name")
                            cursorShape: Qt.PointingHandCursor
                        }
                        Text { text: "Oda Adı"; anchors.centerIn: parent; font.bold: true; color: "#444" }
                    }
                    Rectangle { width: parent.width * 0.18; height: 36; color: "transparent"
                        Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#bbb" }
                        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#bbb" }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: sorter.sortBy("privilege")
                            cursorShape: Qt.PointingHandCursor
                        }
                        Text { text: "Yetki"; anchors.centerIn: parent; font.bold: true; color: "#444" }
                    }
                    Rectangle { width: parent.width * 0.25; height: 36; color: "transparent"
                        Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#bbb" }
                        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#bbb" }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: sorter.sortBy("current")
                            cursorShape: Qt.PointingHandCursor
                        }
                        Text { text: "Kapasite"; anchors.centerIn: parent; font.bold: true; color: "#444" }
                    }
                    // Max sütunu kaldırıldı
                    Rectangle { width: parent.width * 0.1; height: 36; color: "transparent"
                        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#bbb" }
                        Text { text: "Eylem"; anchors.centerIn: parent; font.bold: true; color: "#444" }
                    }
                }

                ListView {
                    id: roomListView
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    anchors.margins: 0
                    y: 36
                    height: parent.height - 36
                    model: roomMenu.roomList
                    clip: true
                    delegate: Row {
                        spacing: 0
                        height: 40
                        Rectangle { width: roomListView.width * 0.15; height: 40; color: "transparent"
                            Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#eee" }
                            Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#eee" }
                            Text {
                                text: roomMenu.roomList[index].id !== undefined ? "ID: " + roomMenu.roomList[index].id : ""
                                color: "#888"
                                font.pointSize: 12
                                anchors.centerIn: parent
                            }
                        }
                        Rectangle {
                            width: roomListView.width * 0.32; height: 40; color: "transparent"
                            Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#eee" }
                            Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#eee" }
                            Text {
                                text: roomMenu.roomList[index].name !== undefined ? roomMenu.roomList[index].name : ""
                                font.pointSize: 14
                                color: "#222"
                                elide: Text.ElideRight
                                anchors.centerIn: parent
                            }
                        }
                        Rectangle {
                            width: roomListView.width * 0.18; height: 40; color: "transparent"
                            Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#eee" }
                            Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#eee" }
                            Text {
                                text: roomMenu.roomList[index].privilege == 1 ? "👑 Sadece Adminler" : "🌍 Herkes"
                                color: roomMenu.roomList[index].privilege == 1 ? "#e67e22" : "#2980b9"
                                font.pointSize: 13
                                anchors.centerIn: parent
                            }
                        }
                        Rectangle {
                            width: roomListView.width * 0.25; height: 40; color: "transparent"
                            Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: "#eee" }
                            Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#eee" }
                            Text {
                                text: (roomMenu.roomList[index].current !== undefined && roomMenu.roomList[index].max !== undefined ? roomMenu.roomList[index].current + "/" + roomMenu.roomList[index].max : "") + " kişi"
                                color: (roomMenu.roomList[index].current !== undefined && roomMenu.roomList[index].max !== undefined && roomMenu.roomList[index].current >= roomMenu.roomList[index].max) ? "#e74c3c" : "#27ae60"
                                font.pointSize: 13
                                anchors.centerIn: parent
                            }
                        }
                        // Max sütunu kaldırıldı
                        Rectangle {
                            width: roomListView.width * 0.1; height: 40; color: "transparent"
                            Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: "#eee" }
                            Button {
                                anchors.centerIn: parent
                                text: "Katıl"
                                width: 80
                                font.bold: true
                                font.pointSize: 13
                                background: Rectangle {
                                    color: enabled ? "#1976D2" : "#B0BEC5"
                                    radius: 8
                                    border.color: enabled ? "#0D47A1" : "#90A4AE"
                                    border.width: 1
                                }
                                contentItem: Text {
                                    text: parent.text
                                    color: enabled ? "white" : "#ECEFF1"
                                    font.bold: true
                                    font.pointSize: 13
                                    horizontalAlignment: Text.AlignHCenter
                                    verticalAlignment: Text.AlignVCenter
                                    anchors.centerIn: parent
                                }
                                hoverEnabled: true
                                opacity: enabled ? 1.0 : 0.5
                                enabled: (roomMenu.roomList[index].current !== undefined && roomMenu.roomList[index].max !== undefined && roomMenu.roomList[index].current < roomMenu.roomList[index].max) && (roomMenu.roomList[index].privilege === 0 || roomMenu.userPrivilege === 1)
                                onClicked: roomMenu.joinRoom(roomMenu.roomList[index].id)
                            }
                        }
                    }
                }

            }
        }
    }

    function joinRoom(roomId) {
        // C++ veya QML üzerinden bağlanacak
        roomMenu.close();
        roomMenu.roomJoined(roomId);
    }

    signal roomJoined(int roomId)
    signal roomCreated(string name, int accessType, string userIds)

    // Import CreateRoomPopup
    Component.onCompleted: {
        if (typeof CreateRoomPopup === "undefined") {
            Qt.include("CreateRoomPopup.qml");
        }
    }
}
