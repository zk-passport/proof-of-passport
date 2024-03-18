// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {Groth16Verifier} from "./Verifier.sol";
import {Base64} from "./libraries/Base64.sol";
import {Formatter} from "./libraries/Formatter.sol";
import "hardhat/console.sol";

contract ProofOfPassport is ERC721Enumerable, Ownable {
    using Strings for uint256;
    using Base64 for *;

    Groth16Verifier public immutable verifier;
    Formatter public formatter;
    address public cscaPubkey = 0x0000000000000000000000000000000000000000;

    mapping(uint256 => bool) public nullifiers;

    struct AttributePosition {
        string name;
        uint256 start;
        uint256 end;
        uint256 index;
    }

    struct Attributes {
        string[7] values;
    }

    AttributePosition[] public attributePositions;

    mapping(uint256 => Attributes) private tokenAttributes;

    constructor(Groth16Verifier v, Formatter f) ERC721("ProofOfPassport", "ProofOfPassport") {
        verifier = v;
        formatter = f;
        setupAttributes();
        transferOwnership(msg.sender);
    }

    function setupAttributes() internal {
        attributePositions.push(AttributePosition("issuing_state", 2, 4, 0));
        attributePositions.push(AttributePosition("name", 5, 43, 1));
        attributePositions.push(AttributePosition("passport_number", 44, 52, 2));
        attributePositions.push(AttributePosition("nationality", 54, 56, 3));
        attributePositions.push(AttributePosition("date_of_birth", 57, 62, 4));
        attributePositions.push(AttributePosition("gender", 64, 64, 5));
        attributePositions.push(AttributePosition("expiry_date", 65, 70, 6));
    }

    function setCSCApubKey(address _CSCApubKey) public onlyOwner {
        cscaPubkey = _CSCApubKey;
    }

    function mint(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[16] memory inputs
    ) public {
        require(verifier.verifyProof(a, b, c, inputs), "Invalid Proof");

        // check that the nullifier has not been used before. Commented out for beta version.
        // require(!nullifiers[inputs[3]], "Signature already nullified");



        // Verify that the public key for RSA matches the hardcoded one
        // for (uint256 i = body_len; i < msg_len - 1; i++) {
        //     require(mailServer.isVerified(domain, i - body_len, inputs[i]), "Invalid: RSA modulus not matched");
        // }
        // inputs[4]

        // Verify that the public key for RSA matches the hardcoded one
        // commented out for now, since hard to keep up with all
        // require(cscaPubkey == inputs[], "Invalid pubkey in inputs");

        // Effects: Mint token
        address addr = address(uint160(inputs[inputs.length - 1])); // generally the last one
        uint256 newTokenId = totalSupply();
        _mint(addr, newTokenId);
        nullifiers[inputs[3]] = true;


        // Set attributes
        uint256[3] memory firstThree = sliceFirstThree(inputs);
        bytes memory charcodes = fieldElementsToBytes(firstThree);
        // console.logBytes1(charcodes[21]);

        Attributes storage attributes = tokenAttributes[newTokenId];

        for (uint i = 0; i < attributePositions.length; i++) {
            AttributePosition memory attribute = attributePositions[i];
            bytes memory attributeBytes = new bytes(attribute.end - attribute.start + 1);
            for (uint j = attribute.start; j <= attribute.end; j++) {
                attributeBytes[j - attribute.start] = charcodes[j];
            }
            string memory attributeValue = string(attributeBytes);
            attributes.values[i] = attributeValue;
            console.log(attribute.name, attributes.values[i]);
        }
    }

    function fieldElementsToBytes(uint256[3] memory publicSignals) public pure returns (bytes memory) {
        uint8[3] memory bytesCount = [31, 31, 26];
        bytes memory bytesArray = new bytes(88); // 31 + 31 + 26

        uint256 index = 0;
        for (uint256 i = 0; i < 3; i++) {
            uint256 element = publicSignals[i];
            for (uint8 j = 0; j < bytesCount[i]; j++) {
                bytesArray[index++] = bytes1(uint8(element & 0xFF));
                element = element >> 8;
            }
        }

        return bytesArray;
    }

    function sliceFirstThree(uint256[16] memory input) public pure returns (uint256[3] memory) {
        uint256[3] memory sliced;

        for (uint256 i = 0; i < 3; i++) {
            sliced[i] = input[i];
        }

        return sliced;
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId,
        uint256 batchSize
    ) internal virtual override {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
        require(from == address(0), "Cannot transfer - Proof of Passport is soulbound");
    }

    function tokenURI(
        uint256 _tokenId
    ) public view virtual override returns (string memory) {
        require(
            _exists(_tokenId),
            "ERC721Metadata: URI query for nonexistent token"
        );
        Attributes memory attributes = tokenAttributes[_tokenId];

        console.log("Issuing state in tokenURI", attributes.values[0]);

        string memory firstName;
        string memory lastName;

        (firstName, lastName) = formatter.formatName(attributes.values[1]);

        bytes memory baseURI = (
            abi.encodePacked(
                '{ "attributes": [',
                    '{"trait_type": "Issuing State", "value": "',
                    formatter.formatCountryName(attributes.values[0]),
                    '"},{"trait_type": "FirstName", "value": "',
                    firstName,
                    '"},{"trait_type": "LastName", "value": "',
                    lastName,
                    '"},{"trait_type": "Passport Number", "value": "',
                    attributes.values[2],
                    '"},{"trait_type": "Nationality", "value": "',
                    formatter.formatCountryName(attributes.values[3]),
                    '"},{"trait_type": "Date of birth", "value": "',
                    formatter.formatDate(attributes.values[4]),
                    '"},{"trait_type": "Gender", "value": "',
                    attributes.values[5],
                    '"},{"trait_type": "Expiry date", "value": "',
                    formatter.formatDate(attributes.values[6]),
                    '"},{"trait_type": "Expired", "value": "',
                    isExpired(_tokenId) ? "Yes" : "No",
                    '"}',
                "],",
                '"description": "Proof of Passport guarantees possession of a valid passport.","external_url": "https://github.com/zk-passport/proof-of-passport","image": "https://i.imgur.com/9kvetij.png","name": "Proof of Passport #',
                _tokenId.toString(),
                '"}'
            )
        );

        return
            string(
                abi.encodePacked(
                    "data:application/json;base64,",
                    baseURI.encode()
                )
            );
    }

    function isExpired(uint256 _tokenId) public view returns (bool) {
        Attributes memory attributes = tokenAttributes[_tokenId];
        uint256 expiryDate = formatter.dateToUnixTimestamp(attributes.values[6]);

        return block.timestamp > expiryDate;
    }
}