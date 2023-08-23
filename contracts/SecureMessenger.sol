// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureMessenger {
    struct EncryptedMessage {
        address sender;
        bytes encryptedMessage;
        uint256 timestamp;
    }

    mapping(address => EncryptedMessage[]) private encryptedMessages;

    modifier onlyParticipants() {
        require(
            msg.sender == participant1 || msg.sender == participant2,
            "Unauthorized"
        );
        _;
    }

    address public participant1;
    address public participant2;

    constructor(address _participant1, address _participant2) {
        participant1 = _participant1;
        participant2 = _participant2;
    }

    function sendEncryptedMessage(
        bytes calldata _encryptedMessage
    ) external onlyParticipants {
        EncryptedMessage memory newMessage = EncryptedMessage({
            sender: msg.sender,
            encryptedMessage: _encryptedMessage,
            timestamp: block.timestamp
        });
        encryptedMessages[msg.sender].push(newMessage);
    }

    function getEncryptedMessages()
        external
        view
        onlyParticipants
        returns (EncryptedMessage[] memory)
    {
        return encryptedMessages[msg.sender];
    }
}
