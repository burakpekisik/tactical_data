import QtQuick 2.15
import QtQuick.Controls 2.15

Item {
    id: chatRoomWindowLoader
    property int roomId: -1
    property string roomName: ""
    property var messages: []
    property var roomKey: null
    signal closed()

    Loader {
        id: chatRoomLoader
        anchors.fill: parent
        active: roomId !== -1
        source: "ChatRoomWindow.qml"
        onLoaded: {
            if (item) {
                item.roomId = chatRoomWindowLoader.roomId;
                item.roomName = chatRoomWindowLoader.roomName;
                item.messages = chatRoomWindowLoader.messages;
                item.roomKey = chatRoomWindowLoader.roomKey;
                item.visible = true;
                item.closed.connect(function() {
                    chatRoomWindowLoader.roomId = -1;
                    chatRoomWindowLoader.closed();
                });
                console.log("[QML] ChatRoomWindowLoader.onLoaded: roomId=", chatRoomWindowLoader.roomId, ", roomKey=", chatRoomWindowLoader.roomKey);
            }
        }
    }
    function open(roomId, roomName, messages, roomKey) {
        // Deactivate loader first to force reload
        chatRoomLoader.active = false;
        // Set all properties
        chatRoomWindowLoader.roomId = roomId;
        chatRoomWindowLoader.roomName = roomName;
        chatRoomWindowLoader.messages = messages || [];
        chatRoomWindowLoader.roomKey = roomKey || null;
        // Reactivate loader (triggers onLoaded)
        chatRoomLoader.active = true;
        console.log("[QML] ChatRoomWindowLoader.open: roomId=", roomId, ", roomKey=", roomKey);
    }
    function close() {
        chatRoomWindowLoader.roomId = -1;
        chatRoomLoader.active = false;
    }
}
