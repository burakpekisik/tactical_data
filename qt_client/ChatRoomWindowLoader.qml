import QtQuick 2.15
import QtQuick.Controls 2.15

Item {
    id: chatRoomWindowLoader
    property int roomId: -1
    property string roomName: ""
    property var messages: []
    signal closed()

    Loader {
        id: chatRoomLoader
        anchors.fill: parent
        active: roomId !== -1
        source: "ChatRoomWindow.qml"
        onLoaded: {
            if (item) {
                item.roomName = chatRoomWindowLoader.roomName;
                item.messages = chatRoomWindowLoader.messages;
                item.visible = true;
                item.closed.connect(function() {
                    chatRoomWindowLoader.roomId = -1;
                    chatRoomWindowLoader.closed();
                });
            }
        }
    }
    function open(roomId, roomName, messages) {
        chatRoomWindowLoader.roomId = roomId;
        chatRoomWindowLoader.roomName = roomName;
        chatRoomWindowLoader.messages = messages || [];
        chatRoomLoader.active = true;
    }
    function close() {
        chatRoomWindowLoader.roomId = -1;
        chatRoomLoader.active = false;
    }
}
