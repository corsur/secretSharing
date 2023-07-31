// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecretStorage {

    struct Secret {
        address signer1;
        address signer2;
        bytes32 secretHash;
    }

    mapping(address => Secret) private secrets;
    
    event SecretRevealed(address indexed party, bytes secret);
    
    function storeSecret(bytes32 hashedSecret, bytes memory secondSignature) public {
        // Gets the address of the second signer and verifies that the message was signed off on by them
        address secondSigner = ECDSA.recover(hashedSecret, secondSignature);

        // Verify that signers don't have a previous secret, we only store one secret at a time
        require(secrets[msg.sender].secretHash == bytes32(0), "Secret already registered");
        require(secrets[secondSigner].secretHash == bytes32(0), "Secret already registered");

        // Store secret, could work out some improvement to avoid storing twice
        // XOR Them together?
        secrets[msg.sender] = Secret(msg.sender, secondSigner, hashedSecret);
        secrets[secondSigner] = Secret(secondSigner, msg.sender, hashedSecret);
    }
    
    function revealSecret(bytes memory secret) public {
        require(secrets[msg.sender].secretHash != 0, "No secret registered");

        bytes32 hashedSecret = keccak256(abi.encodePacked(secret));

        // Create the prefixed message
        bytes memory prefixedMessage = createPrefixedMessage(hashedSecret);

        // Compute the message hash
        bytes32 messageHash = keccak256(prefixedMessage);
        require(secrets[msg.sender].secretHash == messageHash, "Wrong secret");

        // Delete the secret
        address otherSigner = secrets[msg.sender].signer2;
        delete secrets[msg.sender];
        delete secrets[otherSigner];
        emit SecretRevealed(msg.sender, secret);
    }
    
    function getSecretHash(address party) public view returns (bytes32) {
        return secrets[party].secretHash;
    }

    function getSigner1(address party) public view returns (address) {
        return secrets[party].signer1;
    }

    function getSigner2(address party) public view returns (address) {
        return secrets[party].signer2;
    }

    function createPrefixedMessage(bytes32 hashedSecret) public pure returns (bytes memory) {
        string memory prefix = "\x19Ethereum Signed Message:\n66";
        string memory prefixedMessage = string(abi.encodePacked(prefix, bytes32ToString(hashedSecret)));
        bytes memory messageBytes = bytes(prefixedMessage);
        
        return messageBytes;
    }

    function bytes32ToString(bytes32 data) public pure returns (string memory) {
        bytes memory result = new bytes(66);
        result[0] = "0";
        result[1] = "x";
        
        for (uint256 i = 0; i < 32; i++) {
            uint8 byteValue = uint8(bytes1(data << (i * 8)));
            uint8 highNibble = byteValue >> 4;
            uint8 lowNibble = byteValue & 0x0F;
            
            result[i * 2 + 2] = charToHex(highNibble);
            result[i * 2 + 3] = charToHex(lowNibble);
        }
        
        return string(result);
    }
    
    function charToHex(uint8 value) internal pure returns (bytes1) {
        if (value < 10) {
            return bytes1(uint8(bytes1('0')) + value);
        } else {
            return bytes1(uint8(bytes1('a')) + (value - 10));
        }
    }
}
