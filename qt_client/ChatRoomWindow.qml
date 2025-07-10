import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Modern ve beyaz temalı sohbet odası penceresi
ApplicationWindow {
    id: chatWindow
    width: 480
    height: 640
    minimumWidth: 360
    minimumHeight: 480
    visible: true
    title: roomName ? roomName : "Sohbet Odası"
    color: "#f8f8f8"

    property string roomName: "Oda İsmi"
    property var messages: [] // Mesajlar burada tutulacak
    property int roomId: -1   // Oda ID'si (dışarıdan atanmalı)
    property var roomKey: null // Oda anahtarı (dışarıdan atanmalı)

    // --- C++/backend'den mesajlar geldiğinde güncelle ---
    Connections {
        target: clientWrapper
        onChatMessagesReceived: function(roomId, msgArray) {
            console.log("[QML] onChatMessagesReceived: roomId=", roomId, ", msgArray=", JSON.stringify(msgArray));
            chatWindow.messages = msgArray;
        }
        onChatMessagesFailed: function(roomId, error) {
            console.log("[QML] onChatMessagesFailed: roomId=", roomId, ", error=", error);
        }
    }

    // Profesyonel font ailesi (ör: Segoe UI, Roboto, Helvetica Neue, Arial)
    property string chatFont: "'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif"

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Başlık
        Rectangle {
            color: "#ffffff"
            height: 56
            Layout.fillWidth: true
            border.color: "#e0e0e0"
            border.width: 1
            RowLayout {
                anchors.fill: parent
                spacing: 12
                Label {
                    text: chatWindow.roomName
                    font.pixelSize: 22
                    font.family: chatWindow.chatFont
                    color: "#23272e"
                    Layout.alignment: Qt.AlignVCenter
                    leftPadding: 20
                }
                Item { Layout.fillWidth: true }
                Button {
                    text: "Kapat"
                    onClicked: {
                        if (clientWrapper && roomId > 0) {
                            console.log("[QML] Kapat butonuna basıldı, leaveChatRoom çağrılıyor | roomId=", roomId);
                            clientWrapper.leaveChatRoom(roomId);
                        }
                        chatWindow.close();
                    }
                    background: Rectangle { color: "#f2f2f2"; radius: 6 }
                    contentItem: Text {
                        text: parent.text
                        color: "#23272e"
                        font.family: chatWindow.chatFont
                        font.pixelSize: 16
                    }
                    rightPadding: 8
                    leftPadding: 8
                }
                Item { width: 12 } // Sağdan boşluk
            }
        }

        // Mesajlar alanı
        Rectangle {
            color: "#f8f8f8"
            Layout.fillWidth: true
            Layout.fillHeight: true
            border.color: "#e0e0e0"
            border.width: 1
            Flickable {
                id: flick
                anchors.fill: parent
                contentHeight: msgColumn.height
                clip: true
                ScrollBar.vertical: ScrollBar { }
                Column {
                    id: msgColumn
                    width: flick.width
                    spacing: 8
                    Repeater {
                        model: chatWindow.messages
                        delegate: Rectangle {
                            width: parent.width
                            color: modelData.isOwn ? "#e3f2fd" : "#ffffff"
                            radius: 8
                            anchors.right: undefined
                            anchors.left: parent.left
                            anchors.margins: 8
                            height: Math.max(56, msgText.paintedHeight + 32)
                            Column {
                                anchors.fill: parent
                                anchors.margins: 8
                                spacing: 2
                                // Gönderen adı ve ID
                                Row {
                                    spacing: 6
                                    Text {
                                        text: modelData.sender_name ? modelData.sender_name : "?"
                                        color: "#1976D2"
                                        font.bold: true
                                        font.pixelSize: 13
                                        font.family: chatWindow.chatFont
                                    }
                                    Text {
                                        text: modelData.sender_id ? ("(Kullanıcı ID: " + modelData.sender_id + ")") : ""
                                        color: "#888"
                                        font.pixelSize: 12
                                        font.family: chatWindow.chatFont
                                    }
                                }
                                Row {
                                    spacing: 8
                                    Text {
                                        id: msgText
                                        text: modelData.message !== undefined ? modelData.message : (modelData.text !== undefined ? modelData.text : "")
                                        color: "#23272e"
                                        wrapMode: Text.Wrap
                                        font.pixelSize: 16
                                        font.family: chatWindow.chatFont
                                    }
                                    // Saat
                                    Text {
                                        text: {
                                            if (modelData.timestamp) {
                                                var date = new Date(modelData.timestamp * 1000);
                                                return date.getHours().toString().padStart(2, '0') + ':' + date.getMinutes().toString().padStart(2, '0');
                                            } else if (modelData.time) {
                                                return modelData.time;
                                            }
                                            return "";
                                        }
                                        color: "#b0b4be"
                                        font.pixelSize: 12
                                        font.family: chatWindow.chatFont
                                        verticalAlignment: Text.AlignBottom
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Mesaj gönderme alanı
        Rectangle {
            color: "#ffffff"
            height: 64
            Layout.fillWidth: true
            border.color: "#e0e0e0"
            border.width: 1
            RowLayout {
                anchors.fill: parent
                spacing: 8
                Item { width: 16 } // inputun solundan boşluk
                TextField {
                    id: inputField
                    Layout.fillWidth: true
                    placeholderText: "Mesajınızı yazın..."
                    color: "#23272e"
                    font.family: chatWindow.chatFont
                    background: Rectangle {
                        color: "#f8f8f8"
                        radius: 6
                        border.color: "#e0e0e0"
                    }
                    font.pixelSize: 16
                    leftPadding: 12
                    rightPadding: 12
                    verticalAlignment: Text.AlignVCenter
                    Keys.onReturnPressed: sendBtn.clicked()
                }
                Item { width: 8 } // input ile buton arası boşluk
                Button {
                    id: sendBtn
                    text: "Gönder"
                    enabled: inputField.text.length > 0
                    onClicked: {
                        chatWindow.sendMessage(inputField.text)
                        inputField.text = ""
                    }
                    background: Rectangle { color: enabled ? "#1976D2" : "#e0e0e0"; radius: 6 }
                    contentItem: Text {
                        text: parent.text
                        color: enabled ? "#fff" : "#23272e"
                        font.family: chatWindow.chatFont
                        font.pixelSize: 16
                    }
                    width: 90
                    leftPadding: 8
                    rightPadding: 8
                }
                Item { width: 16 } // Gönder butonunun sağından boşluk
            }
        }
    }

    // Mesaj gönderme fonksiyonu (QML tarafında override edilebilir)
    // Mesaj gönderme fonksiyonu (C++/backend'e entegre)
    function sendMessage(text) {
        console.log("[QML] sendMessage çağrıldı | text=", text, "roomId=", roomId, "roomKey=", roomKey);
        if (!text || !clientWrapper || roomId === -1 || !roomKey) {
            console.log("[QML] sendMessage: Eksik parametre! text=", text, "roomId=", roomId, "roomKey=", roomKey);
            return;
        }
        // UI'ya anında ekle (optimistic update)
        var now = new Date();
        var hh = now.getHours().toString().padStart(2, '0');
        var mm = now.getMinutes().toString().padStart(2, '0');
        var userName = clientWrapper.currentUserName ? clientWrapper.currentUserName : "Ben";
        var userId = clientWrapper.currentUserId ? clientWrapper.currentUserId : "";
        console.log("[QML] sendMessage: UI'ya ekleniyor", text, userName, userId, hh + ":" + mm);
        // messages.push({ ... }) satırını değiştir:
        var newMessages = messages.slice();
        newMessages.push({
            message: text,
            isOwn: true,
            sender_name: userName,
            sender_id: userId,
            time: hh + ":" + mm
        });
        messages = newMessages;
        // Backend'e gönder
        console.log("[QML] sendMessage: clientWrapper.sendChatMessage çağrılıyor", roomId, text, roomKey);
        clientWrapper.sendChatMessage(roomId, text, roomKey);
    }
}
