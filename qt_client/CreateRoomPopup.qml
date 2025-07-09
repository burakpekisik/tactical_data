import QtQuick 2.15
import QtQuick.Controls 2.15


Popup {
    id: createRoomPopup
    width: 400
    height: 320
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
    x: (parent ? parent.width : Screen.width) / 2 - width / 2
    y: (parent ? parent.height : Screen.height) / 2 - height / 2

    property string roomName: ""
    property int accessType: 0 // 0: Herkes, 1: Sadece Adminler, 2: Belirli Kullanıcılar
    property string userIds: ""

    signal createRoom(string name, int accessType, string userIds)

    Rectangle {
        anchors.fill: parent
        color: "#f8f8f8"
        border.color: "#ccc"
        radius: 8

        Column {
            anchors.centerIn: parent
            spacing: 18
            width: parent.width - 40

            Text {
                text: "Oda Oluştur"
                font.bold: true
                font.pointSize: 18
                color: "#222"
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }

            TextField {
                id: nameField
                placeholderText: "Oda adı"
                text: createRoomPopup.roomName
                onTextChanged: createRoomPopup.roomName = text
                width: parent.width
            }

            ComboBox {
                id: accessCombo
                width: parent.width
                model: ["Herkes", "Sadece Adminler", "Belirli Kullanıcılar"]
                currentIndex: createRoomPopup.accessType
                onCurrentIndexChanged: createRoomPopup.accessType = currentIndex
            }

            TextField {
                id: userIdsField
                visible: accessCombo.currentIndex === 2
                placeholderText: "Kullanıcı ID'leri (virgülle)"
                text: createRoomPopup.userIds
                onTextChanged: createRoomPopup.userIds = text
                width: parent.width
            }

            Row {
                spacing: 16
                anchors.horizontalCenter: parent.horizontalCenter
                Button {
                    text: "Oluştur"
                    enabled: nameField.text.length > 0 && (accessCombo.currentIndex !== 2 || userIdsField.text.length > 0)
                    onClicked: {
                        console.log("Oluştur tıklandı", nameField.text, accessCombo.currentIndex, userIdsField.text)
                        createRoomPopup.createRoom(nameField.text, accessCombo.currentIndex, userIdsField.text)
                        createRoomPopup.close()
                    }
                }
                Button {
                    text: "İptal"
                    onClicked: createRoomPopup.close()
                }
            }
        }
    }
}
