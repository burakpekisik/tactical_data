import QtQuick 2.15
import QtQuick.Controls 2.15

Popup {
    id: roomMenu
    width: 600
    height: 500
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    property var roomList: [] // Dışarıdan set edilecek [{name, privilege, current, max, id}]
    property int userPrivilege: 0 // Dışarıdan set edilecek

    Rectangle {
        anchors.fill: parent
        color: "#f8f8f8"
        border.color: "#cccccc"
        radius: 8

        Column {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 8

            Text {
                text: "Oda Listesi"
                font.bold: true
                font.pointSize: 18
                color: "#222"
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Rectangle {
                width: parent.width
                height: parent.height - 60
                color: "#fff"
                border.color: "#ccc"
                radius: 6

                ListView {
                    id: roomListView
                    anchors.fill: parent
                    model: roomMenu.roomList
                    delegate: Row {
                        spacing: 8
                        height: 40
                        Rectangle { width: 24; height: 24; color: "transparent"
                            Text { text: "📋"; anchors.centerIn: parent }
                        }
                        Text {
                            text: roomMenu.roomList[index].name !== undefined ? roomMenu.roomList[index].name : ""
                            font.pointSize: 14
                            color: "#222"
                            width: 120
                            elide: Text.ElideRight
                        }
                        Text {
                            text: roomMenu.roomList[index].privilege == 1 ? "👑 Sadece Adminler" : "🌍 Herkes"
                            color: roomMenu.roomList[index].privilege == 1 ? "#e67e22" : "#2980b9"
                            font.pointSize: 13
                            width: 110
                        }
                        Text {
                            text: (roomMenu.roomList[index].current !== undefined && roomMenu.roomList[index].max !== undefined ? roomMenu.roomList[index].current + "/" + roomMenu.roomList[index].max : "") + " kişi"
                            color: (roomMenu.roomList[index].current !== undefined && roomMenu.roomList[index].max !== undefined && roomMenu.roomList[index].current >= roomMenu.roomList[index].max) ? "#e74c3c" : "#27ae60"
                            font.pointSize: 13
                            width: 80
                        }
                        Text {
                            text: roomMenu.roomList[index].id !== undefined ? "ID: " + roomMenu.roomList[index].id : ""
                            color: "#888"
                            font.pointSize: 12
                            width: 60
                        }
                        Button {
                            text: "Katıl"
                            enabled: (roomMenu.roomList[index].current !== undefined && roomMenu.roomList[index].max !== undefined && roomMenu.roomList[index].current < roomMenu.roomList[index].max) && (roomMenu.roomList[index].privilege === 0 || roomMenu.userPrivilege === 1)
                            onClicked: roomMenu.joinRoom(roomMenu.roomList[index].id)
                            width: 60
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
}
